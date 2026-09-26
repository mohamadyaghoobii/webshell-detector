# WebShell Hunter

A defensive, **static** web shell and backdoor hunter for Linux web servers
(Apache, Nginx, PHP, WordPress, Laravel, custom PHP, Node.js, Python, JSP and
ASP/ASPX files found in shared directories or backups).

Its focus is not only finding a suspicious file but explaining **why a web
shell keeps coming back** after redeployments and migrations. It correlates
the web shell with baseline changes, `.user.ini` / `.htaccess` / PHP-FPM
settings, cron jobs, systemd units, deployment hooks, symlinks, unexpected
owners, untracked Git files and upload directories.

> **A detection does not automatically prove that a file is malicious.**
> Every finding is an explained set of indicators for a human to review.

---

## Contents

- [Purpose](#purpose)
- [Threat model](#threat-model)
- [Safety guarantees](#safety-guarantees)
- [Installation and requirements](#installation-and-requirements)
- [Quick start](#quick-start)
- [CLI reference and examples](#cli-reference-and-examples)
- [Detection methodology](#detection-methodology)
- [Scoring methodology](#scoring-methodology)
- [Baseline workflow](#baseline-workflow)
- [Deployment comparison](#deployment-comparison)
- [Persistence hunting](#persistence-hunting)
- [YARA usage](#yara-usage)
- [Reports and exit codes](#reports-and-exit-codes)
- [Configuration](#configuration)
- [False positives](#false-positives)
- [Limitations](#limitations)
- [Incident-response recommendations](#incident-response-recommendations)
- [Project layout](#project-layout)
- [Development](#development)

---

## Purpose

- Find known **and unknown** web shells, obfuscated PHP loaders, command
  execution backdoors, malicious uploaders and code hidden in images.
- Find the **persistence mechanism** that re-creates them: PHP
  `auto_prepend_file`, handler tricks in `.htaccess`, cron/systemd jobs,
  deployment hooks, immutable file attributes, symlinks out of the web root.
- Compare the live tree with a **known-good baseline** or backup to see
  exactly what appeared or changed after deployment.
- Produce explainable terminal, JSON, CSV and self-contained HTML reports that
  are usable in an incident-response case file.

## Threat model

The tool assumes an attacker who can write files through the web application
(file upload, vulnerable plugin, stolen credentials, compromised CI) and wants
the access to survive clean-up and redeployment. Typical techniques covered:

| Technique | How it is detected |
|---|---|
| Classic shells (`system($_GET[...])`, `eval($_POST[...])`) | source-to-sink analysis, sink/source rules |
| Obfuscated loaders (`eval(gzinflate(base64_decode(...)))`) | decoder rules, **static decoding of literals** and re-analysis of the decoded layer |
| Dynamic calls (`$f="sys"."tem"; $f($_POST[x])`, `$_POST['a']($_POST['b'])`) | static string resolver, variable-function analysis |
| Hidden / disguised files (`.cache.php`, `x.jpg.php`, PHP in JPEG) | name, extension, magic-byte and content checks |
| Scripts in upload/media folders (`wp-content/uploads/*.php`) | upload-directory and framework awareness |
| `auto_prepend_file` in `.user.ini`, `php.ini`, `.htaccess`, FPM pools, nginx `PHP_VALUE` | config analysis with target resolution and cross-referencing |
| `.htaccess` making `.jpg`/`.txt` executable | handler rules, correlated with media files containing PHP |
| Cron/systemd/rc jobs re-dropping the shell | `--persistence`, following referenced scripts (read-only) |
| Deploy hooks (git hooks, composer/npm scripts, entrypoints) | `--persistence` deployment-hook checks |
| `chattr +i` on the shell | immutable-attribute check (read-only ioctl) |
| Symlinks to `/etc`, `/tmp`, other users' homes | symlink analysis with safe path containment |
| Files written after the last deployment | baseline, Git state, ctime clustering, timeline |

Out of scope: memory-resident implants, kernel rootkits, database-stored
backdoors (e.g. malicious WordPress options) and compromised binaries.

## Safety guarantees

The scanner is **read-only and static** by default. It never:

- executes, includes, imports or evaluates scanned files (PHP, JS, Python, ...),
- runs commands found in scanned files or discovered binaries,
- contacts URLs, domains or IPs found in files (IOCs are labelled
  `UNVERIFIED STATIC IOC`),
- submits samples anywhere (there is no network code at all),
- deletes or modifies files (quarantine is opt-in and needs
  `--confirm-quarantine`).

Additional hardening:

- Files are opened with `O_NOFOLLOW` and checked against the `lstat` taken
  during the walk; a file replaced or swapped for a symlink mid-scan is
  reported, not followed. Symlinks are never descended into.
- Path containment uses `os.path.commonpath`, never string prefixes
  (`/var/www/html2` is not inside `/var/www/html`).
- Decoding of Base64/gzip/rot13 literals is bounded (zip-bomb safe) and is
  pure data transformation.
- Archives are inspected in memory with member/size/ratio limits; path
  traversal members are reported, never written.
- `--git` runs only `git ls-files` with system/global config ignored,
  `core.fsmonitor=false` and `core.hooksPath=/dev/null`; file modification is
  determined by hashing content ourselves, so no repository filters run.
- YAML is parsed with `yaml.safe_load` only.
- Reports escape all attacker-controlled strings (HTML escaping, CSV formula
  neutralisation); evidence snippets are short, redact long blobs and obvious
  secrets, and escape control characters. Logs never contain payloads.

## Installation and requirements

- Linux, Python **3.10+**
- No mandatory third-party packages: the core scanner uses the standard library.
- Optional: `PyYAML` (YAML config/allowlist; JSON works without it) and
  `yara-python` (for `--yara`).

```bash
git clone <this repository> webshell-hunter
cd webshell-hunter
pip install -r requirements.txt        # optional extras
python3 webshell_hunter.py --help
```

Or install the `webshell-hunter` command: `pip install .` (extras:
`pip install .[yaml,yara]`).

**Single-file release:** `python3 tools/build_zipapp.py` creates
`dist/webshell-hunter.pyz`, which runs anywhere with Python 3.10+:
`python3 webshell-hunter.pyz scan --path /var/www/html`.

Run as a user that can read the whole web root (usually `root` via `sudo`);
unreadable paths are counted and reported, never fatal.

## Quick start

```bash
# Scan a web root
sudo python3 webshell_hunter.py scan --path /var/www/html

# The prototype syntax still works
sudo python3 webshell_hunter.py --path /var/www/html
```

Example output (abridged):

```
[CRITICAL] /var/www/html/wp-content/uploads/2026/09/.cache.php
Score: 109   Confidence: VERY_HIGH   Language: php
Reasons:
  + Attacker-controlled request data ($_GET) is passed directly to system() (command execution) [definitive, +55]
      line 2: system($_GET["cmd"]);
  + Server-side script inside the framework's user-upload area (wordpress:uploads) [strong, +18]
  + Server-side script with execution capability inside an upload directory [strong, +15]
  + Hidden server-side script (dot-file) [moderate, +10]
Confidence: VERY_HIGH - Definitive indicator: Attacker-controlled request data ...
Suggested read-only follow-up:
  $ stat /var/www/html/wp-content/uploads/2026/09/.cache.php
  $ sha256sum /var/www/html/wp-content/uploads/2026/09/.cache.php
  $ lsattr /var/www/html/wp-content/uploads/2026/09/.cache.php
```

## CLI reference and examples

```
webshell-hunter scan         --path DIR [--path DIR ...] [options]
webshell-hunter baseline create --path DIR --output baseline.json
webshell-hunter baseline verify baseline.json
webshell-hunter compare      --old /backup/known-good --new /var/www/html
webshell-hunter investigate  /path/to/file.php [--root DIR]
webshell-hunter timeline     --path DIR [--after DATE] [--before DATE] [--extension php]
```

Common `scan` options:

| Option | Meaning |
|---|---|
| `--path DIR` (repeatable), `--auto-roots` | what to scan (`--auto-roots` = existing common web roots) |
| `--baseline FILE` | compare with a baseline (NEW/MODIFIED/DELETED/PERMISSION_CHANGED/OWNER_CHANGED) |
| `--persistence` | hunt cron/systemd/rc/php-config/deploy-hook persistence |
| `--webserver-config` | inspect `/etc/apache2`, `/etc/httpd`, `/etc/nginx`, ... |
| `--git` | untracked/modified/ignored scripts vs the Git index |
| `--yara PATH` | YARA rules file or directory (optional dependency) |
| `--hash-list FILE` | SHA256 IOC list; exact matches are CRITICAL |
| `--allowlist FILE` / `--show-allowlisted` | false-positive handling |
| `--modified-within 7d`, `--after DATE`, `--before DATE`, `--time-field mtime\|ctime\|either` | time window |
| `--scan-archives` | inspect zip/tar/tgz members in memory |
| `--exclude GLOB`, `--no-default-excludes` | scope (`.git/` and `node_modules/` are skipped by default) |
| `--workers N`, `--executor process\|thread`, `--max-size 20M` | performance |
| `--min-severity LEVEL` | reporting threshold (default LOW) |
| `--json/--csv/--html FILE` | reports |
| `--no-color`, `--quiet`, `--no-snippets`, `--no-commands` | output control |
| `--log-file FILE`, `--verbose`, `--debug`, `--config FILE` | general |
| `--quarantine DIR --confirm-quarantine [--quarantine-copy-only]` | opt-in evidence preservation |

Examples:

```bash
# Everything that changed in the last week, with Git state and an HTML report
sudo python3 webshell_hunter.py scan --path /var/www/html --modified-within 7d --git --html week.html

# Between two dates (ctime cannot be forged with touch)
sudo python3 webshell_hunter.py scan --path /var/www/html --after 2026-09-20 --before 2026-09-27 --time-field ctime

# Several roots, host persistence, web server config, YARA and IOC hashes
sudo python3 webshell_hunter.py scan --auto-roots --persistence --webserver-config \
    --yara rules/ --hash-list iocs.txt --json full.json

# Deep static look at a single sample
sudo python3 webshell_hunter.py investigate /var/www/html/wp-content/uploads/.cache.php

# What appeared around the compromise time?
sudo python3 webshell_hunter.py timeline --path /var/www/html --after 2026-09-20 --extension php --sort ctime
```

## Detection methodology

Each file goes through independent analysers; every hit becomes an
**indicator** with a rule id, category, strength, weight and sanitised
evidence (line number + snippet).

1. **Metadata** - owner/group, mode, inode, timestamps, world-writable,
   setuid, `chattr +i`/`+a` (read via a read-only ioctl), owner anomalies
   (a script owned by `www-data` when 80%+ of scripts are owned by someone
   else), scripts changed after the dominant bulk-deployment ctime cluster.
2. **Names and locations** - known shell names (weak on their own), short or
   random names, hidden files/dirs, double extensions (`x.jpg.php`),
   `x.php.jpg`, trailing dots, mixed-case extensions, unusual PHP extensions,
   scripts in upload/media dirs, framework awareness (WordPress
   `wp-content/uploads`, `mu-plugins`; Laravel public storage and generated
   caches; Drupal/Joomla/Magento media). Directories that mostly contain code
   (e.g. `src/Image/`) are not treated as upload folders.
3. **Content type** - magic-byte sniffing (never trusts the extension), binary
   detection, PHP in images/text, image-header polyglots (`GIF89a<?php`),
   ELF/PE binaries disguised as images.
4. **Rules** (`scanner/signatures.py`) - PHP sinks (`eval`, `assert`,
   `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`,
   `pcntl_exec`, `create_function`, `preg_replace /e`, backticks, callbacks),
   sources, decoders, droppers (writing scripts, self-copy, timestomping,
   read-only chmod), unrestricted uploaders, reverse shells, "immortal"
   respawn loops, known family markers, plus JSP, ASP/ASPX, Node.js, Python
   and Perl/CGI rule sets. A lightweight PHP lexer separates code, strings
   and comments so a comment mentioning `eval()` does not count as a call.
5. **Source-to-sink analysis** (`scanner/phpflow.py`) - tracks request data
   (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, `php://input`,
   HTTP headers) through simple assignments into sinks. Direct flows are
   definitive; flows via variables are strong; sanitised flows
   (`escapeshellarg`, `intval`, ...) are downgraded; data used only as an
   array index (dispatch tables) is not counted.
6. **Dynamic invocation** - a bounded static resolver evaluates *string
   expressions only* (literal concatenation, `chr()`, `base64_decode`,
   `str_rot13`, `strrev`, `gzinflate`, `hex2bin`, `str_replace`...) to recognise
   `$f = "sys"."tem"; $f(...)`, `("sys"."tem")(...)`, `$_POST['f'](...)`,
   `call_user_func($f, ...)`, `${"GLOBALS"}[...]` and variable-variables.
7. **Obfuscation shape** - entropy, extremely long lines, long Base64 blobs,
   hex-escaped payloads, fragment-concatenation chains, nested decoders.
   Encoded literals are **decoded statically** (bounded, up to 3 layers) and
   the decoded text is analysed again; results are marked `[decoded layer N]`.
8. **Configuration** - `.user.ini`, `php.ini`, `.htaccess`, FPM pools, web
   server configs: `auto_prepend_file`/`auto_append_file` (target resolved and
   reported as a relationship), handler mappings for image/text extensions,
   PHP/CGI enabled in upload dirs, `allow_url_include`, SEO cloaking rules,
   modules loaded from unusual paths.
9. **Context** - baseline status, Git status, YARA, IOC hashes.
10. **Correlation** - relationships from configs, cron/systemd lines, scripts
    and includes are matched against scanned files; referenced files outside
    the web root are analysed too. Evidence-backed chains are reported:

```
Likely persistence chain(s) (evidence-backed relationships):

  /etc/cron.d/site-update [CRITICAL]
        |  executes (line 1)
        v
  /usr/local/bin/site-update.sh [CRITICAL]
        |  writes/copies (line 2)
        v
  /var/www/html/wp-content/uploads/.x.php [CRITICAL]
  The destination file is independently classified as CRITICAL because:
  Attacker-controlled request data ($_REQUEST) is passed directly to eval() ...
```

Chains are only built from static evidence (a directive, a cron line, a
script line) - never from guesses.

## Scoring methodology

```
score = Σ over categories  min(category_cap, Σ weights of distinct rules in that category)
severity = band(score), raised to the highest min_severity floor of any indicator
```

- **Rules count once** per file (repeats only increase the occurrence count).
- **Category caps** stop many weak hits of one kind from adding up (e.g.
  `sink` is capped at 10, `source` at 4, `obfuscation` at 25).
- **Combinations** add points only when independent signals co-occur, e.g.
  decoder + eval, source + exec (no proven flow), upload dir + exec, new/
  untracked + upload dir + exec (→ CRITICAL floor), known marker + exec.
- **Severity floors** encode "this alone is enough": direct request data into
  `system()`/`eval()` is CRITICAL; an IOC hash match is CRITICAL;
  `auto_prepend_file` pointing into `/tmp` is HIGH.

Default bands (configurable in `scoring.thresholds`):

| Score | Severity |
|---|---|
| 0-9 | INFO (not reported by default) |
| 10-19 | LOW |
| 20-34 | MEDIUM |
| 35-59 | HIGH |
| 60+ | CRITICAL |

Illustration of the strength ladder:

| Evidence | Typical result |
|---|---|
| `base64_decode()` alone | weak, +2 → INFO |
| `base64_decode` + `eval` (separate statements) | +2 +4 +12 (combination) → LOW/MEDIUM |
| `eval(base64_decode("..."))` | loader pattern +30 → HIGH |
| `eval(gzinflate(base64_decode("...")))` whose decoded layer contains `system($_REQUEST[...])` | CRITICAL |
| `system($_POST['c'])` | definitive flow → CRITICAL, confidence VERY_HIGH |
| new untracked PHP in `uploads/` with `$_POST` → `system()` and high entropy | CRITICAL, VERY_HIGH |

**Confidence** is separate from severity and reflects the *independence*
of the evidence:

| Confidence | Rule |
|---|---|
| VERY_HIGH | a definitive indicator, or strong indicators from ≥2 categories, or strong + ≥2 other corroborating categories |
| HIGH | one strong indicator, or moderate indicators across ≥3 categories |
| MEDIUM | moderate indicator(s), or ≥3 weak ones |
| LOW | only weak indicators |

Weights can be tuned per rule id (`scoring.weights`); rule ids are included
in JSON/HTML/CSV reports.

## Baseline workflow

```bash
# 1. Initial scan of the current state
sudo python3 webshell_hunter.py scan --path /var/www/html --json initial.json

# 2. After cleaning / redeploying from a trusted source, record a known-good baseline
sudo python3 webshell_hunter.py baseline create --path /var/www/html --output baseline.json
#    Store it OFF the server (or read-only): an attacker could edit it.
python3 webshell_hunter.py baseline verify baseline.json      # integrity digest check

# 3. Later compromise check
sudo python3 webshell_hunter.py scan \
    --path /var/www/html \
    --baseline baseline.json \
    --persistence \
    --html incident-report.html
```

The baseline stores relative path, SHA256, size, mtime, mode, uid, gid, type
and symlink target. The scan reports `NEW`, `MODIFIED`, `DELETED`,
`PERMISSION_CHANGED`, `OWNER_CHANGED`, `TYPE_CHANGED` and `SYMLINK_CHANGED`;
new or modified server-side scripts gain risk (a new PHP file in an upload
directory with execution capability is CRITICAL).

## Deployment comparison

Because the shell survives redeployments, compare a known-good artefact (a
backup, a fresh checkout or the release tarball extracted elsewhere) with the
live tree:

```bash
sudo python3 webshell_hunter.py compare --old /backup/known-good --new /var/www/html --html diff.html
```

It reports new/removed files, hash, permission, owner and symlink changes, and
statically analyses the changed files (`--all-findings` also reports suspicious
unchanged files). Files that exist only in the live tree and sit in paths
your deployment does not replace (uploads, shared storage, mounted volumes)
are prime suspects for persistence.

## Persistence hunting

`--persistence` statically inspects (read-only; access errors never stop the scan):

- cron: `/etc/crontab`, `/etc/anacrontab`, `/etc/cron.*`, `/var/spool/cron`
- systemd: `/etc/systemd/system`, `/usr/lib/systemd/system`, `/lib/systemd/system`, user units
- `/etc/rc.local`, `/etc/init.d`, `/etc/profile.d`, supervisor configs, `/etc/ld.so.preload`
- PHP configuration: `/etc/php*`, FPM pools (`php_admin_value[auto_prepend_file]`), remi/opt layouts
- deployment hooks in each web root: non-sample `.git/hooks/*`, composer/npm
  lifecycle scripts, root-level `*.sh`, `Dockerfile*`, entrypoints

Each line is checked for references to the web root, `curl`/`wget` (piped to
an interpreter, or saving scripts), Base64 decoding, `/tmp`, `/var/tmp`,
`/dev/shm`, hidden paths, inline interpreter code (`php -r`, `python -c`),
reverse-shell patterns, `chattr +i`, timestomping and writes of script files.
Scripts executed by cron/systemd are followed (up to depth 2) and analysed
the same way - never executed. Persistence findings are printed in a separate
section, and linked to web shell findings through the chain analysis.

`--webserver-config` adds `/etc/apache2`, `/etc/httpd`, `/etc/nginx` and
similar: prepend directives, image extensions routed to PHP-FPM, modules
loaded from temp/home/web paths, references into `/tmp`/`/dev/shm` and hidden
directories.

## YARA usage

```bash
pip install yara-python
sudo python3 webshell_hunter.py scan --path /var/www/html --yara rules/
```

`rules/php.yar`, `jsp.yar`, `asp.yar` and `generic.yar` contain defensive,
characteristic-based rules (no payloads). Optional rule metadata feeds the
scoring: `weight`, `strength` (`weak|moderate|strong|definitive`),
`min_severity` and `tags` (e.g. `sink:exec` to participate in combinations).
YARA matches in-memory data already read by the scanner. If `yara-python` is
missing or rules fail to compile, a warning is printed and scanning continues.

## Reports and exit codes

- **Terminal**: coloured when supported (`--no-color`, `NO_COLOR`), findings
  sorted by severity, reasons with strengths/weights, snippets, suggested
  read-only follow-up commands, persistence chains, baseline changes and
  summary statistics.
- **JSON** (`--json`): full machine-readable result including indicators,
  evidence, metadata, relationships, chains, baseline changes and stats.
- **CSV** (`--csv`): one row per finding (formula-injection safe).
- **HTML** (`--html`): single self-contained file, no JavaScript/CDN:
  executive summary, scan information, severity counts, critical/high
  findings, persistence indicators and chains, baseline changes, file
  metadata, detection reasons and hashes.

| Exit code | Meaning |
|---|---|
| 0 | no meaningful findings (INFO only) |
| 1 | LOW or MEDIUM findings |
| 2 | HIGH findings |
| 3 | CRITICAL findings |
| 4 | scanner/runtime error (bad arguments, missing path, invalid config/baseline) |

Allowlisted findings do not affect the exit code.

## Configuration

`config/default.yaml` documents every setting; pass your copy with
`--config`. CLI options override the file. Highlights:

```yaml
scanner:
  max_file_size_mb: 20
  workers: 8
exclude:
  - var/cache/**
persistence:
  enabled: false
yara:
  enabled: true
  rules: rules/
scoring:
  weights:
    php.sink.eval: 2
```

## False positives

- Legitimate software does use `eval`, `exec`, `base64_decode`, dynamic
  callbacks and `auto_prepend_file` (e.g. WAF plugins such as Wordfence).
  Single primitives are weak by design; review the reasons, not just the score.
- Tested against clean upstream WordPress and the Laravel framework source
  trees: WordPress produces no reported findings; the Laravel source tree
  produces a handful of LOW/MEDIUM findings in its own test-suite and a bundled
  helper binary.
- Use the allowlist (`--allowlist`, see `config/allowlist.example.yaml`):
  **prefer SHA256 entries** - a path allowlist also hides a malicious file
  placed at that path. `vendor_dirs` only suppress findings up to
  `vendor_suppress_up_to` (default LOW), and IOC hash matches are never
  suppressed.
- `mode: mark` keeps allowlisted findings in reports, flagged as such.

## Limitations

- Static heuristics, not a PHP interpreter: heavily custom obfuscation,
  encryption keyed by request data, or payloads fetched at run time may only
  show up as weak/moderate indicators (entropy, dynamic calls, decoders).
- Taint tracking is intra-file and assignment-based; it does not follow
  function parameters, object properties or includes.
- Encrypted/compiled PHP (ionCube, Zend Guard), minified JS and packed
  binaries cannot be analysed meaningfully.
- Timestamps can be forged (`touch`); ctime cannot be set from user space but
  is reset by copies, restores and some deployment tools.
- A baseline is only as trustworthy as the moment and place it was created.
- Database-resident backdoors, memory-only implants and rootkits are out of scope.

## Incident-response recommendations

The preferred response to a finding is **REPORT → HASH → PRESERVE →
INVESTIGATE**, not delete:

1. **Preserve before touching anything**: save the JSON/HTML reports, record
   hashes, and copy evidence (`--quarantine DIR --confirm-quarantine
   --quarantine-copy-only` stores `sha256.sample` files with mode 0400 and a
   manifest with the original path and metadata). Consider a full disk/VM
   snapshot first.
2. **Establish the timeline**: `timeline --sort ctime`, web server access
   logs around the file's ctime (requests to the shell and to upload
   endpoints), `last`/auth logs.
3. **Find the re-infection path**: run with `--persistence
   --webserver-config --git` and a baseline; read the persistence chains.
   Check `lsattr` for immutable files, `.user.ini`/`.htaccess` in every
   directory, PHP-FPM pools, cron for all users, systemd timers, CI/CD
   secrets and deployment scripts, and persistent volumes/shared directories
   that deployments do not replace.
4. **Contain**: block the entry point (patch the vulnerable plugin/upload
   form), rotate credentials (database, admin users, SSH keys, API tokens,
   CI secrets), disable PHP execution in upload directories.
5. **Eradicate from a trusted source**: redeploy from a verified artefact,
   remove persistence mechanisms, then create a fresh baseline and store it
   off-host.
6. **Monitor**: schedule `scan --baseline ... --persistence` (exit code ≥ 2
   → alert) and keep reports for comparison.

## Project layout

```
webshell_hunter.py          entry point (also accepts the prototype's --path syntax)
scanner/
  cli.py                    argument parsing, commands, exit codes
  engine.py                 scan orchestration, parallelism, post-processing
  filesystem.py             safe walking, exclusions, upload/framework context, symlinks
  metadata.py               lstat metadata, O_NOFOLLOW reads, hashing, magic bytes, chattr flags
  analyzer.py               per-file content analysis (shared by files, archive members, referenced files)
  phplex.py                 position-preserving PHP lexer (code/string/comment views)
  phpflow.py                source-to-sink, dynamic invocation, static string resolution
  signatures.py             declarative rule table (PHP, JSP, ASP, Node, Python, Perl, generic)
  entropy.py                entropy, line length, binary detection
  configfiles.py            .user.ini / php.ini / .htaccess / web server config analysis
  persistence.py            cron/systemd/rc/php-config/deploy-hook hunting
  webserver.py              web server configuration scanning
  correlation.py            cross-references and persistence chains
  scoring.py                scoring model, combinations, confidence
  baseline.py               baseline create/load/compare, tree snapshots
  gitstate.py               hardened, hook-free Git index comparison
  yara_engine.py            optional YARA integration
  archives.py               in-memory zip/tar inspection with bomb/traversal protection
  allowlist.py, hashlist.py, iocs.py, evidence.py, timeline.py, investigate.py, quarantine.py
  reporting/                terminal, JSON/CSV, HTML
rules/                      defensive YARA rules
config/                     default.yaml, allowlist and IOC examples
tests/                      pytest suite with synthetic, non-functional samples
tools/build_zipapp.py       single-file release builder
```

## Development

```bash
pip install -r requirements-dev.txt
python3 -m pytest -q
```

Test samples are synthetic and inert: each starts with an unconditional
`exit`, and dangerous identifiers are assembled from fragments at run time,
so the repository contains no functional payloads.

## License

MIT - see [LICENSE](LICENSE).
