"""Safe, in-memory inspection of zip/tar archives (``--scan-archives``).

Nothing is extracted to disk. Protections:

* member count, per-member size and total decompressed byte limits,
* compression-ratio check against zip bombs,
* decompression through a byte-counting reader (tar.gz/bz2/xz),
* path traversal / absolute member names are *reported*, never written,
* nested archives are not recursed into.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Iterator

from .metadata import SERVER_SIDE_EXT
from .models import Evidence, Indicator, Strength


class LimitExceeded(Exception):
    pass


class LimitedReader(io.RawIOBase):
    """Wraps a stream and raises once more than *limit* bytes were read."""

    def __init__(self, raw, limit: int) -> None:
        self.raw = raw
        self.limit = limit
        self.count = 0

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        data = self.raw.read(len(b))
        self.count += len(data)
        if self.count > self.limit:
            raise LimitExceeded(f"archive decompressed size exceeds {self.limit} bytes")
        b[: len(data)] = data
        return len(data)


@dataclass
class Member:
    name: str
    data: bytes | None
    size: int
    is_symlink: bool = False
    link_target: str | None = None


@dataclass
class ArchiveReport:
    indicators: list[Indicator] = field(default_factory=list)
    members: list[Member] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    member_count: int = 0


def is_archive(name: str) -> bool:
    n = name.lower()
    return n.endswith((".zip", ".jar", ".war", ".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tbz2",
                       ".tar.xz", ".txz"))


def _unsafe_name(name: str) -> bool:
    p = PurePosixPath(name.replace("\\", "/"))
    return name.startswith(("/", "\\")) or ".." in p.parts or (len(name) > 1 and name[1] == ":")


def inspect_archive(path: str, max_members: int, max_member: int, max_total: int,
                    max_ratio: int) -> ArchiveReport:
    rep = ArchiveReport()
    try:
        if path.lower().endswith((".zip", ".jar", ".war")):
            _zip(path, rep, max_members, max_member, max_total, max_ratio)
        else:
            _tar(path, rep, max_members, max_member, max_total)
    except LimitExceeded as exc:
        rep.indicators.append(Indicator("archive.limit", "archive", f"Archive inspection stopped: {exc}",
                                        4, Strength.WEAK))
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, lzma.LZMAError, ValueError) as exc:
        rep.errors.append(f"{path}: {exc}")
    scripts = [m.name for m in rep.members if PurePosixPath(m.name).suffix.lower() in SERVER_SIDE_EXT]
    if scripts:
        rep.indicators.append(Indicator("archive.contains_scripts", "archive",
                                        f"Archive contains {len(scripts)} server-side script(s)", 3, Strength.WEAK,
                                        [Evidence(None, ", ".join(scripts[:5]))]))
    return rep


def _flag_name(rep: ArchiveReport, name: str) -> None:
    if _unsafe_name(name):
        rep.indicators.append(Indicator("archive.path_traversal", "archive",
                                        "Archive member with absolute path or '..' traversal (zip-slip)",
                                        14, Strength.MODERATE, [Evidence(None, name[:160])]))


def _zip(path: str, rep: ArchiveReport, max_members: int, max_member: int, max_total: int,
         max_ratio: int) -> None:
    total = 0
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            rep.member_count += 1
            if rep.member_count > max_members:
                raise LimitExceeded(f"more than {max_members} members")
            if info.is_dir():
                continue
            _flag_name(rep, info.filename)
            if info.compress_size and info.file_size / max(1, info.compress_size) > max_ratio:
                rep.indicators.append(Indicator("archive.bomb_ratio", "archive",
                                                f"Suspicious compression ratio for {info.filename[:80]} (zip bomb?)",
                                                6, Strength.WEAK))
                continue
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                target = zf.read(info)[:4096].decode("utf-8", "replace") if info.file_size < 4096 else "?"
                rep.members.append(Member(info.filename, None, info.file_size, True, target))
                continue
            if info.file_size > max_member:
                rep.members.append(Member(info.filename, None, info.file_size))
                continue
            with zf.open(info) as fh:
                data = fh.read(max_member + 1)[:max_member]
            total += len(data)
            if total > max_total:
                raise LimitExceeded(f"total inspected bytes exceed {max_total}")
            rep.members.append(Member(info.filename, data, info.file_size))


def _open_stream(path: str, limit: int):
    raw = open(path, "rb")
    head = raw.read(6)
    raw.seek(0)
    if head.startswith(b"\x1f\x8b"):
        stream = gzip.GzipFile(fileobj=raw)
    elif head.startswith(b"BZh"):
        stream = bz2.BZ2File(raw)
    elif head.startswith(b"\xfd7zXZ"):
        stream = lzma.LZMAFile(raw)
    else:
        stream = raw
    return raw, io.BufferedReader(LimitedReader(stream, limit))


def _tar(path: str, rep: ArchiveReport, max_members: int, max_member: int, max_total: int) -> None:
    raw, stream = _open_stream(path, max_total)
    try:
        with tarfile.open(fileobj=stream, mode="r|") as tf:
            for info in tf:
                rep.member_count += 1
                if rep.member_count > max_members:
                    raise LimitExceeded(f"more than {max_members} members")
                _flag_name(rep, info.name)
                if info.issym() or info.islnk():
                    rep.members.append(Member(info.name, None, 0, True, info.linkname))
                    if _unsafe_name(info.linkname) or info.linkname.startswith("/"):
                        rep.indicators.append(Indicator("archive.symlink_escape", "archive",
                                                        "Archive symlink member points outside the archive",
                                                        8, Strength.MODERATE,
                                                        [Evidence(None, f"{info.name} -> {info.linkname}"[:160])]))
                    continue
                if not info.isfile():
                    continue
                if info.size > max_member:
                    rep.members.append(Member(info.name, None, info.size))
                    continue
                fh = tf.extractfile(info)
                data = fh.read(max_member) if fh else b""
                rep.members.append(Member(info.name, data, info.size))
    finally:
        raw.close()


def iter_members(rep: ArchiveReport) -> Iterator[Member]:
    yield from rep.members


def archive_size_ok(path: str, limit: int) -> bool:
    try:
        return os.path.getsize(path) <= limit
    except OSError:
        return False
