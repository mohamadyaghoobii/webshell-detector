"""Configuration: built-in defaults, optional YAML/JSON file, CLI overrides.

The built-in defaults below are authoritative; ``config/default.yaml``
mirrors them for documentation and as a starting point for customisation.
PyYAML is optional: without it, JSON configuration files still work.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

DEFAULT_CONFIG: dict[str, Any] = {
    "scanner": {
        "max_file_size_mb": 20,
        "workers": 8,
        "report_min_severity": "LOW",
        "snippets": True,
        "max_snippet_length": 160,
        "max_evidence_per_indicator": 3,
        "entropy_sample_bytes": 65536,
        "media_tail_check_bytes": 262144,
        "decode_layers": 3,
        "max_decoded_bytes": 4 * 1024 * 1024,
        "suggest_commands": True,
        "default_excludes": True,
    },
    # Directory/file globs relative to the scan root that are not walked.
    # Attackers sometimes hide inside vendor/ or node_modules/, so these are
    # only excluded when scanner.default_excludes is true.
    "default_excludes": [".git/**", "node_modules/**"],
    "exclude": [],
    "filenames": {
        # Matching on the file *stem* (name without extension), case-insensitive.
        "known_webshell": [
            # (a few names are assembled at runtime so this file does not
            # itself match the content-marker rules)
            "c99", "c100", "r57", "wso", "wso2", "".join(("b37", "4k")), "filesman", "shell",
            "webshell", "backdoor", "cmd", "cmdshell", "alfa", "alfashell",
            "".join(("indo", "xploit")), "priv8", "sh3ll", "phpspy",
            "bypass", "symlink", "mini", "minishell", "weevely", "china_chopper",
            "chopper", "godzilla", "behinder", "k2ll33d", "madspot", "kacak",
        ],
        "suspicious": ["mailer", "upload", "up", "uploader", "adminer", "x", "xx", "xxx",
                       "test1", "info", "phpinfo", "config.bak"],
        "short_name_max_length": 3,
    },
    "upload_dirs": {
        # Directory *components* (not substrings) that indicate user content.
        "strong": ["upload", "uploads", "uploaded", "media", "image", "images", "img",
                   "files", "attachment", "attachments", "avatar", "avatars",
                   "userfiles", "user_uploads", "pictures", "photos", "documents"],
        "weak": ["cache", "tmp", "temp", "storage", "data", "assets", "static", "public"],
        # Framework paths where compiled PHP is expected; weak location rules skip them.
        "benign_generated": ["bootstrap/cache/**", "storage/framework/**", "var/cache/**",
                             "cache/smarty/**", "templates_c/**"],
    },
    "hidden_allowlist": [
        ".htaccess", ".htpasswd", ".gitignore", ".gitattributes", ".gitkeep", ".keep",
        ".editorconfig", ".well-known", ".user.ini", ".DS_Store", ".babelrc",
        ".eslintrc", ".eslintrc.js", ".eslintrc.json", ".prettierrc", ".npmrc",
        ".nvmrc", ".dockerignore", ".browserslistrc", ".stylelintrc", ".env.example",
        ".php-cs-fixer.php", ".php-cs-fixer.dist.php", ".php_cs", ".php_cs.dist",
        ".styleci.yml", ".travis.yml", ".gitlab-ci.yml", ".github", ".circleci",
        ".vscode", ".idea", ".phpstorm.meta.php", ".scrutinizer.yml", ".codeclimate.yml",
        ".env", ".npmignore", ".jshintrc", ".csslintrc", ".gitmodules", ".mailmap",
    ],
    "scoring": {
        # Severity is the highest band whose threshold the score reaches.
        "thresholds": {"LOW": 10, "MEDIUM": 20, "HIGH": 35, "CRITICAL": 60},
        # Maximum points a single category can contribute.
        "category_caps": {
            "sink": 10,
            "source": 4,
            "obfuscation": 25,
            "obfuscated_execution": 35,
            "source_to_sink": 60,
            "dynamic_invocation": 40,
            "known_marker": 40,
            "filename": 10,
            "location": 25,
            "content_mismatch": 30,
            "metadata": 20,
            "timeline": 8,
            "config_persistence": 45,
            "dropper": 25,
            "network": 25,
            "baseline": 15,
            "git": 12,
            "yara": 40,
            "ioc_hash": 100,
            "cross_reference": 30,
            "combination": 45,
            "persistence": 80,
            "archive": 20,
        },
        # Per-rule weight overrides: {"php.sink.eval": 2}
        "weights": {},
    },
    "allowlist": {
        "mode": "exclude",           # exclude | mark
        "paths": [],                 # exact relative/absolute paths or globs
        "hashes": [],                # SHA256
        "regex": [],                 # regex applied to the relative path
        # Vendor directories: findings up to vendor_suppress_up_to are allowlisted,
        # anything stronger is still reported (attackers hide in vendor/ too).
        "vendor_dirs": ["vendor/**", "node_modules/**", "wp-includes/**", "wp-admin/**"],
        "vendor_suppress_up_to": "LOW",
        "never_suppress_ioc_hash": True,
    },
    "persistence": {
        "enabled": False,
        "locations": [
            "/etc/crontab", "/etc/anacrontab", "/etc/cron.d", "/etc/cron.hourly",
            "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
            "/var/spool/cron", "/etc/systemd/system", "/usr/lib/systemd/system",
            "/lib/systemd/system", "/run/systemd/system", "/etc/rc.local", "/etc/init.d",
            "/etc/profile.d", "/etc/ld.so.preload", "/etc/supervisor", "/etc/supervisord.d",
            "/root/.config/systemd/user", "/home/*/.config/systemd/user",
        ],
        "php_config_locations": [
            "/etc/php", "/etc/php.ini", "/etc/php.d", "/etc/php-fpm.d", "/etc/php-fpm.conf",
            "/usr/local/etc/php", "/usr/local/lib/php.ini", "/opt/*/etc/php*",
            "/etc/opt/remi/*/php.ini", "/etc/opt/remi/*/php.d",
        ],
        "max_files": 20000,
        "max_file_size": 1048576,
        "report_min_score": 12,
        "follow_scripts_depth": 2,
    },
    "webserver_config": {
        "enabled": False,
        "locations": ["/etc/apache2", "/etc/httpd", "/etc/nginx", "/usr/local/apache2/conf",
                      "/usr/local/nginx/conf", "/etc/lighttpd", "/etc/caddy"],
    },
    "yara": {"enabled": False, "rules": None, "timeout": 30},
    "baseline": {"path": None},
    "git": {"enabled": False},
    "archives": {
        "enabled": False,
        "max_members": 5000,
        "max_member_size_mb": 10,
        "max_total_mb": 256,
        "max_ratio": 150,
    },
    "iocs": {
        "enabled": True,
        "min_severity": "MEDIUM",
        "max_per_type": 50,
        "ignore_domains": [
            "w3.org", "php.net", "wordpress.org", "schema.org", "github.com",
            "googleapis.com", "gstatic.com", "gravatar.com", "jquery.com", "example.com",
            "example.org", "mozilla.org", "apache.org", "microsoft.com", "xmlsoap.org",
            "purl.org", "json-schema.org", "opensource.org", "gnu.org", "fsf.org",
            "wordpress.com", "laravel.com", "symfony.com", "drupal.org", "joomla.org",
        ],
    },
    "hash_lists": [],
    "quarantine": {"min_severity": "CRITICAL"},
}


class ConfigError(Exception):
    """Raised for unreadable or invalid configuration."""


def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge *override* into a copy of *base*."""
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def load_structured_file(path: str | Path) -> Any:
    """Load a YAML or JSON document without executing anything.

    YAML is parsed with ``yaml.safe_load`` only.
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {p}: {exc}") from exc
    if p.suffix.lower() == ".json":
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"invalid JSON in {p}: {exc}") from exc
    try:
        import yaml  # type: ignore
    except ImportError:
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(
                f"{p} looks like YAML but PyYAML is not installed "
                "(pip install PyYAML), or use a JSON config file"
            ) from exc
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:  # type: ignore[attr-defined]
        raise ConfigError(f"invalid YAML in {p}: {exc}") from exc


def load_config(path: str | Path | None) -> dict[str, Any]:
    """Return the effective configuration (defaults merged with *path*)."""
    if not path:
        return copy.deepcopy(DEFAULT_CONFIG)
    data = load_structured_file(path) or {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    return deep_merge(DEFAULT_CONFIG, data)


def load_allowlist_file(path: str | Path) -> dict[str, Any]:
    """Load a standalone allowlist file (YAML/JSON with an ``allowlist`` key,
    or a mapping of the allowlist keys directly)."""
    data = load_structured_file(path) or {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: allowlist must be a mapping")
    return data.get("allowlist", data)
