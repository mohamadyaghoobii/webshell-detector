"""File metadata, safe reading, hashing and content-type sniffing.

Files are opened with ``O_NOFOLLOW`` and verified against the ``lstat``
result taken during the walk, so a file swapped for a symlink (or replaced)
mid-scan is detected rather than followed.
"""

from __future__ import annotations

import errno
import fcntl
import grp
import hashlib
import os
import pwd
import stat
import struct
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .models import FileMetadata
from .utils import safe_relpath

# Linux FS_IOC_GETFLAGS (read-only query of chattr attributes)
_FS_IOC_GETFLAGS = 0x80086601 if struct.calcsize("P") == 8 else 0x80046601
_FS_IMMUTABLE_FL = 0x00000010
_FS_APPEND_FL = 0x00000020

SERVER_SIDE_EXT = {
    ".php", ".php2", ".php3", ".php4", ".php5", ".php6", ".php7", ".php8", ".phtml", ".pht",
    ".phps", ".phar", ".pgif", ".shtml", ".inc", ".module", ".ctp",
    ".asp", ".aspx", ".ashx", ".asmx", ".ascx", ".asa", ".cer", ".cshtml", ".vbhtml",
    ".jsp", ".jspx", ".jspf", ".jsw", ".jsv", ".jhtml",
    ".cgi", ".pl", ".pm", ".py", ".rb", ".sh",
}
PHP_EXT = {".php", ".php2", ".php3", ".php4", ".php5", ".php6", ".php7", ".php8", ".phtml",
           ".pht", ".phps", ".phar", ".pgif", ".inc", ".module", ".ctp"}
UNUSUAL_PHP_EXT = {".php2", ".php3", ".php4", ".php5", ".php6", ".php7", ".php8", ".pht",
                   ".phps", ".phar", ".pgif", ".phtml"}
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".ico", ".bmp", ".svg", ".tif",
             ".tiff", ".avif", ".heic"}
MEDIA_EXT = IMAGE_EXT | {".mp3", ".mp4", ".webm", ".ogg", ".wav", ".avi", ".mov", ".pdf",
                         ".woff", ".woff2", ".ttf", ".otf", ".eot", ".swf"}
ARCHIVE_EXT = {".zip", ".tar", ".tgz", ".gz", ".tbz2", ".bz2", ".txz", ".xz", ".jar", ".war"}
TEXT_EXT = {".js", ".mjs", ".cjs", ".ts", ".css", ".html", ".htm", ".txt", ".json", ".xml",
            ".md", ".csv", ".yml", ".yaml", ".ini", ".conf", ".htaccess", ".log", ".sql",
            ".tpl", ".twig", ".vue", ".map", ".svg", ".env", ".lock", ".po", ".pot"}

EXPECTED_MAGIC = {
    ".jpg": {"jpeg"}, ".jpeg": {"jpeg"}, ".png": {"png"}, ".gif": {"gif"},
    ".webp": {"webp"}, ".ico": {"ico", "png"}, ".bmp": {"bmp"}, ".pdf": {"pdf"},
    ".zip": {"zip"}, ".jar": {"zip"}, ".war": {"zip"}, ".gz": {"gzip"}, ".tgz": {"gzip"},
    ".bz2": {"bzip2"}, ".xz": {"xz"}, ".tif": {"tiff"}, ".tiff": {"tiff"},
    ".woff": {"woff"}, ".woff2": {"woff2"}, ".mp4": {"mp4"}, ".mp3": {"mp3"},
}

_MAGIC: list[tuple[bytes, str]] = [
    (b"\xff\xd8\xff", "jpeg"), (b"\x89PNG\r\n\x1a\n", "png"), (b"GIF87a", "gif"),
    (b"GIF89a", "gif"), (b"%PDF-", "pdf"), (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"),
    (b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"), (b"\xfd7zXZ\x00", "xz"), (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"), (b"\x7fELF", "elf"), (b"\xca\xfe\xba\xbe", "java-class"),
    (b"\x00asm", "wasm"), (b"wOFF", "woff"), (b"wOF2", "woff2"), (b"OggS", "ogg"),
    (b"ID3", "mp3"), (b"\x00\x00\x01\x00", "ico"), (b"II*\x00", "tiff"), (b"MM\x00*", "tiff"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"), (b"SQLite format 3\x00", "sqlite"),
]


@dataclass
class ReadResult:
    data: bytes
    truncated: bool
    sha256: str
    size: int
    fs_flags: list[str]
    sha1: str | None = None
    md5: str | None = None


class FileChangedError(Exception):
    """The file changed type/identity between the walk and the read."""


@lru_cache(maxsize=1024)
def user_name(uid: int) -> str | None:
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, OverflowError):
        return None


@lru_cache(maxsize=1024)
def group_name(gid: int) -> str | None:
    try:
        return grp.getgrgid(gid).gr_name
    except (KeyError, OverflowError):
        return None


def sniff_magic(head: bytes) -> str | None:
    """Identify common binary formats from their leading bytes."""
    for magic, name in _MAGIC:
        if head.startswith(magic):
            return name
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    if head[4:8] == b"ftyp":
        return "mp4"
    if head[:2] == b"MZ" and len(head) > 64:
        return "pe"
    if head[:2] == b"BM" and len(head) > 26 and b"\x00" in head[:26]:
        return "bmp"
    return None


def guess_content_type(head: bytes, is_binary: bool) -> str:
    """Best-effort content label (never trusts the extension)."""
    magic = sniff_magic(head)
    if magic:
        return magic
    if is_binary:
        return "binary"
    low = head[:4096].lower()
    if b"<?php" in low or b"<?=" in low:
        return "php"
    if b"<%@" in low or b"<jsp:" in low:
        return "jsp/asp"
    if low.lstrip().startswith(b"#!"):
        return "script"
    if low.lstrip().startswith((b"<svg", b"<?xml")):
        return "xml/svg"
    if b"<html" in low or b"<!doctype html" in low:
        return "html"
    return "text"


def collect_metadata(path: Path, root: Path, st: os.stat_result | None = None) -> FileMetadata:
    """Collect lstat-based metadata (never follows symlinks)."""
    st = st or os.lstat(path)
    md = FileMetadata(path=str(path), relpath=safe_relpath(path, root))
    fill_from_stat(md, st)
    md.extension = path.suffix.lower() if path.suffix else (
        path.name.lower() if path.name.startswith(".") else "")
    if stat.S_ISLNK(st.st_mode):
        md.file_type = "symlink"
        try:
            md.link_target = os.readlink(path)
        except OSError:
            md.link_target = None
    elif stat.S_ISDIR(st.st_mode):
        md.file_type = "dir"
    elif stat.S_ISREG(st.st_mode):
        md.file_type = "file"
    else:
        md.file_type = "other"
    try:
        md.realpath = os.path.realpath(path)
    except (OSError, ValueError):
        md.realpath = None
    return md


def fill_from_stat(md: FileMetadata, st: os.stat_result) -> None:
    md.size = st.st_size
    md.uid = st.st_uid
    md.gid = st.st_gid
    md.owner = user_name(st.st_uid)
    md.group = group_name(st.st_gid)
    md.mode = f"{stat.S_IMODE(st.st_mode):04o}"
    md.permissions = stat.filemode(st.st_mode)
    md.mtime = st.st_mtime
    md.ctime = st.st_ctime
    md.atime = st.st_atime
    md.inode = st.st_ino
    md.device = st.st_dev
    md.nlink = st.st_nlink


def _fs_flags(fd: int) -> list[str]:
    """Read chattr flags (immutable/append-only) via a read-only ioctl."""
    try:
        buf = fcntl.ioctl(fd, _FS_IOC_GETFLAGS, struct.pack("l" if struct.calcsize("P") == 8 else "i", 0))
        value = struct.unpack("l" if struct.calcsize("P") == 8 else "i", buf)[0]
    except OSError:
        return []
    flags = []
    if value & _FS_IMMUTABLE_FL:
        flags.append("immutable")
    if value & _FS_APPEND_FL:
        flags.append("append-only")
    return flags


def open_nofollow(path: str | os.PathLike, expected: os.stat_result | None = None) -> int:
    """Open a regular file read-only without following symlinks.

    Raises FileChangedError when the opened object is not a regular file or
    differs from *expected* (inode/device), which indicates a race.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) \
        | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise FileChangedError("path became a symlink during the scan") from exc
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise FileChangedError("path is no longer a regular file")
        if expected is not None and (st.st_ino != expected.st_ino or st.st_dev != expected.st_dev):
            raise FileChangedError("file was replaced during the scan")
    except BaseException:
        os.close(fd)
        raise
    return fd


def read_file(path: str | os.PathLike, max_bytes: int, expected: os.stat_result | None = None,
              all_hashes: bool = False, want_flags: bool = True) -> ReadResult:
    """Stream-hash the whole file, keeping at most *max_bytes* in memory."""
    fd = open_nofollow(path, expected)
    try:
        flags = _fs_flags(fd) if want_flags else []
        h256 = hashlib.sha256()
        h1 = hashlib.sha1() if all_hashes else None
        h5 = hashlib.md5(usedforsecurity=False) if all_hashes else None
        kept = bytearray()
        total = 0
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            total += len(block)
            h256.update(block)
            if h1 is not None:
                h1.update(block)
            if h5 is not None:
                h5.update(block)
            if len(kept) < max_bytes:
                kept.extend(block[: max_bytes - len(kept)])
        return ReadResult(bytes(kept), total > max_bytes, h256.hexdigest(), total, flags,
                          h1.hexdigest() if h1 else None, h5.hexdigest() if h5 else None)
    finally:
        os.close(fd)


def read_tail(path: str | os.PathLike, nbytes: int, expected: os.stat_result | None = None) -> bytes:
    """Read the last *nbytes* of a file (used for media files that are too large)."""
    fd = open_nofollow(path, expected)
    try:
        size = os.fstat(fd).st_size
        os.lseek(fd, max(0, size - nbytes), os.SEEK_SET)
        return os.read(fd, nbytes)
    finally:
        os.close(fd)


def file_hashes(path: str | os.PathLike) -> dict[str, str]:
    """SHA256/SHA1/MD5 of a file (for investigation output)."""
    r = read_file(path, 0, all_hashes=True, want_flags=False)
    return {"sha256": r.sha256, "sha1": r.sha1 or "", "md5": r.md5 or ""}
