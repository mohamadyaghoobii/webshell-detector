"""Declarative regex rules.

Individual rules are *weak-to-moderate* on purpose: functions such as
``eval`` or ``system`` are not malicious on their own. Strong conclusions
come from the contextual analysers (``sourcesink``, ``dynamic``) and from
the combination logic in ``scoring``.

Each rule is counted at most once per file (occurrences are recorded but do
not add score), and every category has a cap - see ``config.DEFAULT_CONFIG``.

Note: marker strings are written with character classes (``Files[M]an``)
so that this source file does not itself contain the literal markers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .evidence import LineIndex, snippet_at
from .models import Indicator, Strength

W, M, S, D = Strength.WEAK, Strength.MODERATE, Strength.STRONG, Strength.DEFINITIVE

ANY = "any"
SERVER_LANGS = {"php", "jsp", "asp", "node", "python", "perl", "shell"}

# A call not preceded by -> / :: / $ / identifier characters (i.e. a global
# function call, not a method call such as $pdo->exec()).
_G = r"(?<![\w$])(?<!->)(?<!::)"


@dataclass(frozen=True)
class Rule:
    id: str
    pattern: str
    weight: int
    category: str
    strength: Strength
    description: str
    languages: frozenset[str]
    view: str = "codeonly"            # raw | nocomment | codeonly
    tags: frozenset[str] = frozenset()
    min_severity: str | None = None
    flags: int = re.I
    compiled: re.Pattern[str] | None = field(default=None, compare=False, hash=False)
    # Keyword groups (lowercase). The rule runs only if every group has at
    # least one member present in the text.
    keywords: tuple[tuple[str, ...], ...] = ()
    global_call: bool = False          # match must not be a method call / part of an identifier


def _r(id_: str, pattern: str, weight: int, category: str, strength: Strength,
       description: str, langs: str | set[str] = "php", view: str = "codeonly",
       tags: tuple[str, ...] = (), min_severity: str | None = None,
       flags: int = re.I) -> Rule:
    languages = frozenset({langs} if isinstance(langs, str) else langs)
    global_call = pattern.startswith(_G)
    if global_call:
        # Checked in Python after matching: a leading lookbehind disables the
        # regex engine's literal-prefix search and makes rules ~4x slower.
        pattern = pattern[len(_G):]
    return Rule(id_, pattern, weight, category, strength, description, languages,
                view, frozenset(tags), min_severity, flags, global_call=global_call)


RULES: list[Rule] = [
    # ------------------------------------------------------------------ PHP sinks
    _r("php.sink.eval", _G + r"eval\s*\(", 4, "sink", W,
       "Uses eval() (dynamic code evaluation)", tags=("sink:eval",)),
    _r("php.sink.assert", _G + r"assert\s*\(\s*(?:\$[A-Za-z_]\w*\s*\)|\$_|['\"]|@|base64|str_rot13|gz)", 4, "sink", W,
       "Uses assert() with a string/variable argument (can evaluate code on old PHP)",
       view="nocomment", tags=("sink:eval",)),
    _r("php.sink.create_function", _G + r"create_function\s*\(", 4, "sink", W,
       "Uses create_function() (deprecated dynamic code creation)", tags=("sink:eval",)),
    _r("php.sink.system", _G + r"system\s*\(", 4, "sink", W,
       "Uses system() (OS command execution)", tags=("sink:exec",)),
    _r("php.sink.exec", _G + r"exec\s*\(", 4, "sink", W,
       "Uses exec() (OS command execution)", tags=("sink:exec",)),
    _r("php.sink.shell_exec", _G + r"shell_exec\s*\(", 4, "sink", W,
       "Uses shell_exec() (OS command execution)", tags=("sink:exec",)),
    _r("php.sink.passthru", _G + r"passthru\s*\(", 4, "sink", W,
       "Uses passthru() (OS command execution)", tags=("sink:exec",)),
    _r("php.sink.popen", _G + r"popen\s*\(", 3, "sink", W,
       "Uses popen() (process pipe)", tags=("sink:exec",)),
    _r("php.sink.proc_open", _G + r"proc_open\s*\(", 3, "sink", W,
       "Uses proc_open() (process execution)", tags=("sink:exec",)),
    _r("php.sink.pcntl_exec", _G + r"pcntl_exec\s*\(", 5, "sink", M,
       "Uses pcntl_exec() (replaces process with a program)", tags=("sink:exec",)),
    _r("php.sink.preg_replace_e",
       r"preg_replace\s*\(\s*(['\"])([^\w\s\\])(?:(?!\2).){0,300}\2[a-zA-Z]*e[a-zA-Z]*\1",
       15, "obfuscated_execution", S,
       "preg_replace() with the /e modifier (evaluates the replacement as PHP code)",
       view="nocomment", tags=("sink:eval",), min_severity="MEDIUM"),
    _r("php.sink.include_var", _G + r"(?:include|require)(?:_once)?\b\s*\(?\s*\$", 1, "sink", W,
       "Includes a file whose path comes from a variable", tags=("sink:include",)),
    _r("php.callback.dangerous_literal",
       _G + r"(?:call_user_func(?:_array)?|array_map|array_filter|array_walk(?:_recursive)?|"
       r"usort|uasort|uksort|register_shutdown_function|register_tick_function|"
       r"forward_static_call(?:_array)?|iterator_apply|ob_start|set_error_handler|"
       r"set_exception_handler)\s*\([^;]{0,80}?['\"]\s*(?:system|exec|shell_exec|passthru|"
       r"popen|proc_open|pcntl_exec|assert|create_function)\s*['\"]",
       22, "dynamic_invocation", S,
       "Passes a command-execution/eval function name as a callback",
       view="nocomment", tags=("sink:exec", "dyn:strong"), min_severity="HIGH"),
    # ---------------------------------------------------------------- PHP sources
    _r("php.source.request", r"\$_(?:GET|POST|REQUEST)\b", 2, "source", W,
       "Reads HTTP request parameters ($_GET/$_POST/$_REQUEST)",
       view="nocomment", tags=("source",)),
    _r("php.source.cookie", r"\$_COOKIE\b", 2, "source", W,
       "Reads cookies ($_COOKIE)", view="nocomment", tags=("source", "source:cookie")),
    _r("php.source.files", r"\$_FILES\b", 1, "source", W,
       "Handles uploaded files ($_FILES)", view="nocomment", tags=("source",)),
    _r("php.source.header",
       r"\$_SERVER\s*\[\s*['\"]HTTP_(?!HOST\b|ACCEPT|REFERER\b)\w+|getallheaders\s*\(|"
       r"apache_request_headers\s*\(", 2, "source", W,
       "Reads HTTP request headers", view="nocomment", tags=("source", "source:header")),
    _r("php.source.raw_input", r"php://input", 2, "source", W,
       "Reads the raw request body (php://input)", view="nocomment", tags=("source",)),
    # --------------------------------------------------------- PHP decoders/obfuscation
    _r("php.decode.base64", _G + r"base64_decode\s*\(", 2, "obfuscation", W,
       "Uses base64_decode()", tags=("decoder",)),
    _r("php.decode.gzinflate", _G + r"gzinflate\s*\(", 3, "obfuscation", W,
       "Uses gzinflate()", tags=("decoder",)),
    _r("php.decode.gzuncompress", _G + r"gzuncompress\s*\(", 3, "obfuscation", W,
       "Uses gzuncompress()", tags=("decoder",)),
    _r("php.decode.gzdecode", _G + r"gzdecode\s*\(", 2, "obfuscation", W,
       "Uses gzdecode()", tags=("decoder",)),
    _r("php.decode.rot13", _G + r"str_rot13\s*\(", 3, "obfuscation", W,
       "Uses str_rot13()", tags=("decoder",)),
    _r("php.decode.uudecode", _G + r"convert_uudecode\s*\(", 4, "obfuscation", M,
       "Uses convert_uudecode() (rare outside obfuscated code)", tags=("decoder",)),
    _r("php.decode.hex2bin", _G + r"hex2bin\s*\(", 1, "obfuscation", W,
       "Uses hex2bin()", tags=("decoder",)),
    _r("php.decode.pack_hex", _G + r"pack\s*\(\s*['\"]H\*?['\"]", 3, "obfuscation", W,
       "Uses pack('H*') hex decoding", view="nocomment", tags=("decoder",)),
    _r("php.decode.strrev", _G + r"strrev\s*\(", 1, "obfuscation", W,
       "Uses strrev()", tags=("decoder",)),
    _r("php.decode.openssl", _G + r"(?:openssl_decrypt|mcrypt_decrypt)\s*\(", 2, "obfuscation", W,
       "Decrypts data at runtime (openssl_decrypt/mcrypt_decrypt)", tags=("decoder",)),
    _r("php.decode.urldecode", _G + r"(?:raw)?urldecode\s*\(", 1, "obfuscation", W,
       "Uses urldecode()/rawurldecode()", tags=("decoder:weak",)),
    _r("php.obf.nested_decoders",
       _G + r"(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|"
       r"convert_uudecode|hex2bin|rawurldecode|urldecode)\s*\(\s*@?\s*(?:base64_decode|gzinflate|"
       r"gzuncompress|gzdecode|str_rot13|strrev|convert_uudecode|hex2bin|rawurldecode|urldecode)\s*\(",
       10, "obfuscation", M, "Nested decoding functions (layered encoding)",
       tags=("decoder", "obf:strong")),
    _r("php.obf.eval_decoded",
       _G + r"(?:eval|assert|create_function)\s*\(\s*@?\s*(?:[a-z_0-9]+\s*\(\s*@?\s*){0,4}?"
       r"(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode|hex2bin|"
       r"strrev|openssl_decrypt|rawurldecode)\s*\(",
       30, "obfuscated_execution", S,
       "Evaluates the output of a decoding function (eval(decoder(...)) loader pattern)",
       tags=("sink:eval", "decoder", "loader"), min_severity="MEDIUM"),
    _r("php.obf.chr_chain", r"(?:chr\s*\(\s*(?:0x[0-9a-f]+|\d+)\s*\)\s*\.\s*){5,}", 8,
       "obfuscation", M, "Long chr() concatenation chain (hides strings)",
       tags=("obf:strong",)),
    _r("php.obf.globals_indirection",
       r"\$\{\s*\$\{|\$\{\s*['\"]GLOBALS['\"]\s*\}|\$GLOBALS\s*\[\s*['\"][^'\"]{1,40}['\"]\s*\]"
       r"\s*(?:\[\s*[^\]]{1,20}\]\s*)?\(", 10, "obfuscation", M,
       "Calls functions through $GLOBALS / ${...} indirection", view="nocomment",
       tags=("obf:strong", "dyn:weak")),
    _r("php.obf.varvar", r"\$\$[A-Za-z_]|\$\{\s*\$[A-Za-z_]", 2, "obfuscation", W,
       "Uses variable variables ($$name / ${$name})", tags=("obf:weak",)),
    _r("php.obf.superglobal_split",
       r"['\"]_(?:P|PO|POS|G|GE|R|RE|REQ|C|CO|COO)['\"]\s*\.\s*['\"]", 12, "obfuscation", S,
       "Builds a superglobal name ($_POST/$_GET...) from string fragments",
       view="nocomment", tags=("obf:strong", "source")),
    _r("php.obf.reversed_name",
       r"['\"](?:metsys|cexe|cexe_llehs|urhtssap|nepop|nepo_corp|tressa|lave|"
       r"edoced_46esab|etalfnizg|31tor_rts|noitcnuf_etaerc)['\"]", 12, "obfuscation", S,
       "Contains a reversed dangerous function name (strrev obfuscation)",
       view="nocomment", tags=("obf:strong",)),
    _r("php.obf.error_suppressed_exec",
       r"@\s*(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(", 3,
       "obfuscation", W, "Suppresses errors on an execution function (@system/@eval)",
       tags=("obf:weak",)),
    _r("php.obf.goto_spaghetti", r"(?:\bgoto\s+\w+\s*;[\s\S]{0,200}){15,}", 6,
       "obfuscation", M, "Excessive goto jumps (control-flow obfuscation)",
       tags=("obf:strong",)),
    _r("php.shell.preamble",
       r"(?:error_reporting\s*\(\s*0\s*\)|@?ini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?(?:0|off))"
       r"[\s\S]{0,400}?(?:set_time_limit\s*\(\s*0\s*\)|ignore_user_abort\s*\(\s*(?:1|true)\s*\))",
       3, "obfuscation", W, "Hides errors and removes execution time limits (common web shell preamble)",
       view="nocomment"),
    # ---------------------------------------------------------- PHP includes/droppers
    _r("php.include.suspicious_target",
       _G + r"(?:include|require)(?:_once)?\b\s*\(?\s*[^;]{0,120}?"
       r"(?:['\"](?:https?|ftp|php://input|php://filter|data:|zip://|phar://|expect://)|"
       r"/tmp/|/dev/shm/|/var/tmp/|\.(?:jpe?g|png|gif|ico|bmp|svg|txt|log|css|dat|tmp)['\"])",
       16, "dropper", S,
       "Includes a remote, temporary or non-PHP file (image/text/ico) as code",
       view="nocomment", tags=("sink:include", "include:suspicious"), min_severity="MEDIUM"),
    _r("php.dropper.write_script",
       _G + r"(?:file_put_contents|fopen|copy|rename|move_uploaded_file|symlink|link)\s*\([^;]{0,300}?"
       r"\.(?:php\d?|phtml|pht|phar|inc|jsp|aspx?|htaccess|user\.ini)\b",
       8, "dropper", M, "Writes, copies or renames a server-side script/config file",
       view="nocomment", tags=("dropper",)),
    _r("php.dropper.self_copy",
       _G + r"(?:file_put_contents|copy|fwrite|rename)\s*\([^;]{0,200}__FILE__|"
       r"file_get_contents\s*\(\s*__FILE__\s*\)", 8, "dropper", M,
       "Reads or copies its own source (__FILE__) - self-replication pattern",
       view="nocomment", tags=("dropper",)),
    _r("php.dropper.timestomp",
       _G + r"touch\s*\([^;,]{1,200},\s*(?:\d{9,}|filemtime|strtotime|mktime|time\s*\(\s*\)\s*-)",
       10, "dropper", M, "Sets file timestamps explicitly with touch() (possible timestomping)",
       view="nocomment", tags=("dropper", "timestomp")),
    _r("php.dropper.readonly_chmod", _G + r"chmod\s*\([^;]{1,200},\s*0?4[04]4\s*\)", 4,
       "dropper", W, "Makes a file read-only with chmod() (resists cleanup)",
       view="nocomment", tags=("dropper",)),
    _r("php.dropper.remote_fetch",
       _G + r"(?:file_get_contents|fopen|curl_init|copy)\s*\(\s*['\"](?:https?|ftp)://", 3,
       "network", W, "Fetches content from a hard-coded remote URL", view="nocomment",
       tags=("remote_fetch",)),
    _r("php.uploader.unrestricted",
       _G + r"(?:move_uploaded_file|copy)\s*\(\s*\$_FILES\s*\[[^;]{0,120}\]\s*\[\s*['\"]tmp_name['\"]\s*\]"
       r"\s*,\s*[^;]{0,120}?\$_(?:FILES\s*\[[^;]{0,120}\]\s*\[\s*['\"]name['\"]|POST|GET|REQUEST)",
       22, "dropper", S,
       "File uploader that saves to a user-controlled filename (no validation evident)",
       view="nocomment", tags=("dropper", "uploader"), min_severity="MEDIUM"),
    _r("php.extract_request", _G + r"(?:extract|parse_str|import_request_variables)\s*\(\s*"
       r"(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER)|file_get_contents\s*\(\s*['\"]php://input)",
       10, "source_to_sink", M,
       "Imports request data into local variables (extract/parse_str on request input)",
       view="nocomment", tags=("source", "var_injection")),
    _r("php.network.reverse_shell",
       _G + r"(?:fsockopen|stream_socket_client|socket_create|socket_connect)\s*\([\s\S]{0,600}?"
       r"(?:/bin/(?:ba|z|da)?sh|cmd\.exe|proc_open|shell_exec|passthru|popen)",
       22, "network", S, "Socket connection combined with a shell (reverse-shell pattern)",
       view="nocomment", tags=("sink:exec", "reverse_shell"), min_severity="HIGH"),
    _r("php.daemon.immortal",
       r"ignore_user_abort\s*\(\s*(?:1|true)\s*\)[\s\S]{0,600}?set_time_limit\s*\(\s*0\s*\)"
       r"[\s\S]{0,1200}?(?:while\s*\(\s*(?:1|true|!0)\s*\)|for\s*\(\s*;\s*;\s*\))",
       14, "dropper", S,
       "Runs an endless loop detached from the request (ignore_user_abort + set_time_limit(0))"
       " - typical of self-respawning 'immortal' shells",
       view="nocomment", tags=("dropper", "respawn")),
    _r("php.mail.spam_mailer",
       r"(?:\bLeaf\s*PHPMailer|\bmass\s*mailer|\bmailer\s*inbox\b)", 12, "known_marker", M,
       "Mass-mailer tool marker", view="raw", tags=("marker",)),
    # ------------------------------------------------------------- Known markers (raw)
    _r("marker.filesman", r"Files[M]an", 30, "known_marker", S,
       "Known web shell marker: Files-Man (WSO family)", ANY, "raw", ("marker",), "MEDIUM", 0),
    _r("marker.c99", r"c99[s]hell|c99_[b]uff_prepare|c99sh_[s]url", 30, "known_marker", S,
       "Known web shell marker: c99", ANY, "raw", ("marker",), "MEDIUM"),
    _r("marker.r57", r"r57[s]hell|r57_[p]wd_hash", 30, "known_marker", S,
       "Known web shell marker: r57", ANY, "raw", ("marker",), "MEDIUM"),
    _r("marker.wso", r"\bW[S]O\s+[0-9](?:\.[0-9])*\b|wso_[v]ersion|\$default_[a]ction\s*=\s*['\"]Files",
       30, "known_marker", S, "Known web shell marker: WSO", ANY, "raw", ("marker",), "MEDIUM", 0),
    _r("marker.b374", r"b37[4]k", 30, "known_marker", S,
       "Known web shell marker: b-374k", ANY, "raw", ("marker",), "MEDIUM"),
    _r("marker.indo_alfa", r"Indo[X]ploit|Alfa[T]eam|ALFA_[D]ATA|Mini\s*[S]hell\s*By", 30,
       "known_marker", S, "Known web shell marker (Indo-Xploit/Alfa-Team/Mini-Shell family)",
       ANY, "raw", ("marker",), "MEDIUM"),
    _r("marker.weevely", r"\$kh\s*=\s*['\"][0-9a-f]{8}['\"];\s*\$kf\s*=\s*['\"][0-9a-f]{8}['\"]",
       30, "known_marker", S, "Known web shell marker: Weevely agent key layout",
       "php", "raw", ("marker",), "MEDIUM"),
    _r("marker.generic_title",
       r"<title>[^<]{0,40}(?:sh[e3]ll\s*by\b|backdoor|priv8|b[y]pass\s*shell|web\s*sh[e3]ll\s*(?:v?\d|by\b))[^<]{0,40}</title>",
       14, "known_marker", M, "HTML title typical of web shell user interfaces",
       ANY, "raw", ("marker",)),
    # ----------------------------------------------------------------- Generic text
    _r("generic.reverse_shell",
       r"/dev/tcp/\d{1,3}\.\d{1,3}|\bnc(?:at)?\s+(?:-\w+\s+)*-e\s+/bin/|bash\s+-i\s*>&|"
       r"mkfifo\s+/tmp/[^;]{0,40};\s*(?:cat|nc)|socat\s+[^\n]{0,60}exec:",
       20, "network", S, "Reverse-shell command pattern", ANY, "raw",
       ("reverse_shell", "sink:exec"), "HIGH"),
    _r("generic.sensitive_files", r"/etc/(?:shadow|passwd)\b|/proc/self/environ", 3, "network", W,
       "References sensitive system files (/etc/passwd, /etc/shadow, /proc/self/environ)",
       ANY, "raw"),
    # ------------------------------------------------------------------------ JSP
    _r("jsp.sink.runtime_exec", r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(", 5,
       "sink", W, "Java Runtime.exec() (OS command execution)", "jsp", "raw", ("sink:exec",)),
    _r("jsp.sink.processbuilder", r"new\s+ProcessBuilder\s*\(", 5, "sink", W,
       "Java ProcessBuilder (OS command execution)", "jsp", "raw", ("sink:exec",)),
    _r("jsp.sink.scriptengine", r"ScriptEngineManager|\.getEngineByName\s*\(", 4, "sink", W,
       "Java ScriptEngine (dynamic script evaluation)", "jsp", "raw", ("sink:eval",)),
    _r("jsp.source.param", r"request\s*\.\s*(?:getParameter|getHeader|getInputStream|getReader|"
       r"getParameterValues)\s*\(", 2, "source", W, "Reads HTTP request data", "jsp", "raw",
       ("source",)),
    _r("jsp.flow.direct",
       r"(?:\.exec\s*\(|new\s+ProcessBuilder\s*\()[^;]{0,200}?request\s*\.\s*(?:getParameter|getHeader)",
       50, "source_to_sink", D, "HTTP request parameter passed directly to OS command execution",
       "jsp", "raw", ("flow:direct", "sink:exec", "source"), "CRITICAL"),
    _r("jsp.memshell.defineclass",
       r"(?:defineClass|ClassLoader)[\s\S]{0,800}?(?:Base64|BASE64Decoder|decodeBuffer|Cipher)|"
       r"(?:Base64|BASE64Decoder|Cipher)[\s\S]{0,800}?defineClass", 24, "obfuscated_execution", S,
       "Defines Java classes from decoded/decrypted data (Behinder/Godzilla-style loader)",
       "jsp", "raw", ("sink:eval", "obf:strong"), "HIGH"),
    # ------------------------------------------------------------------ ASP / ASPX
    _r("asp.sink.wscript", r"WScript\.Shell|Shell\.Application", 5, "sink", W,
       "WScript.Shell / Shell.Application (command execution)", "asp", "raw", ("sink:exec",)),
    _r("asp.sink.process", r"ProcessStartInfo|System\.Diagnostics\.Process|Process\s*\.\s*Start\s*\(",
       5, "sink", W, ".NET process execution", "asp", "raw", ("sink:exec",)),
    _r("asp.source.request", r"Request\s*(?:\.\s*(?:Form|QueryString|Item|Cookies|Headers|"
       r"BinaryRead|InputStream)|\s*\(\s*['\"])", 2, "source", W, "Reads HTTP request data",
       "asp", "raw", ("source",)),
    _r("asp.flow.eval_request",
       r"\b(?:eval|execute|executeglobal)\s*\(?\s*request\s*(?:\.|\(|\[)", 50, "source_to_sink", D,
       "HTTP request data passed directly to eval/Execute", "asp", "raw",
       ("flow:direct", "sink:eval", "source"), "CRITICAL"),
    _r("asp.flow.jscript_unsafe", r"eval\s*\([^;]{0,120}?,\s*['\"]unsafe['\"]\s*\)", 40,
       "source_to_sink", D, "JScript.NET eval(..., \"unsafe\") (China Chopper-style)", "asp", "raw",
       ("sink:eval",), "CRITICAL"),
    _r("asp.loader.assembly_load",
       r"Assembly\s*\.\s*Load\s*\([\s\S]{0,200}?(?:FromBase64String|Decrypt|TransformFinalBlock)",
       24, "obfuscated_execution", S, "Loads a .NET assembly from decoded/decrypted data",
       "asp", "raw", ("sink:eval", "obf:strong"), "HIGH"),
    _r("asp.flow.cmd_request",
       r"(?:cmd\.exe|/c\s*[\"']?\s*\+)[^;\n]{0,160}?Request\s*(?:\.|\(|\[)", 40, "source_to_sink", D,
       "Builds a cmd.exe command from request data", "asp", "raw",
       ("flow:direct", "sink:exec", "source"), "CRITICAL"),
    # ------------------------------------------------------------------- Node.js
    _r("node.sink.child_process", r"child_process", 3, "sink", W,
       "Uses Node.js child_process (command execution)", "node", "raw", ("sink:exec",)),
    _r("node.sink.exec_sync", r"\b(?:execSync|spawnSync|execFileSync)\s*\(", 3, "sink", W,
       "Uses synchronous Node.js process execution", "node", "raw", ("sink:exec",)),
    _r("node.sink.eval", r"(?:eval|new\s+Function|vm\s*\.\s*runIn\w*Context)\s*\(",
       3, "sink", W, "Dynamic JavaScript evaluation (eval/new Function/vm)", "node", "raw",
       ("sink:eval",)),
    _r("node.source.request", r"\breq(?:uest)?\s*\.\s*(?:query|body|params|headers|cookies)\b", 2,
       "source", W, "Reads HTTP request data (req.query/body/params)", "node", "raw", ("source",)),
    _r("node.flow.direct",
       r"(?:exec(?:Sync|File(?:Sync)?)?|spawn(?:Sync)?|eval|new\s+Function)\s*\("
       r"[^;\n]{0,160}?\breq(?:uest)?\s*\.\s*(?:query|body|params|headers|cookies)\b",
       50, "source_to_sink", D, "HTTP request data passed directly to exec/eval", "node", "raw",
       ("flow:direct", "sink:exec", "source"), "CRITICAL"),
    _r("node.obf.eval_buffer",
       r"(?:eval|new\s+Function)\s*\(\s*(?:Buffer\s*\.\s*from|atob)\s*\(", 20, "obfuscated_execution", S,
       "Evaluates decoded Base64 data (eval(Buffer.from(...)))", "node", "raw",
       ("sink:eval", "decoder", "obf:strong"), "MEDIUM"),
    # -------------------------------------------------------------------- Python
    _r("py.sink.exec", r"\bos\s*\.\s*(?:system|popen|exec\w*)\s*\(|\bsubprocess\s*\.\s*"
       r"(?:Popen|call|run|check_output|check_call|getoutput|getstatusoutput)\s*\(|\bpty\s*\.\s*spawn\s*\(",
       3, "sink", W, "Python OS command execution", "python", "raw", ("sink:exec",)),
    _r("py.sink.eval", r"(?<![\w.])(?:eval|exec)\s*\(|__import__\s*\(\s*['\"]os['\"]", 3, "sink", W,
       "Python dynamic evaluation (eval/exec/__import__)", "python", "raw", ("sink:eval",)),
    _r("py.source.request", r"\brequest\s*\.\s*(?:args|form|values|GET|POST|data|json|cookies|"
       r"headers|get_json|body)\b", 2, "source", W, "Reads HTTP request data", "python", "raw",
       ("source",)),
    _r("py.flow.direct",
       r"(?:\bos\s*\.\s*(?:system|popen)|\bsubprocess\s*\.\s*\w+|(?<![\w.])eval|(?<![\w.])exec)\s*\("
       r"[^\n]{0,160}?\brequest\s*\.\s*(?:args|form|values|GET|POST|data|json|cookies|headers)\b",
       50, "source_to_sink", D, "HTTP request data passed directly to exec/eval", "python", "raw",
       ("flow:direct", "sink:exec", "source"), "CRITICAL"),
    _r("py.obf.exec_decoded",
       r"(?:exec|eval)\s*\(\s*(?:[\w.]+\s*\(\s*){0,3}(?:base64\s*\.\s*b64decode|zlib\s*\.\s*decompress|"
       r"marshal\s*\.\s*loads|codecs\s*\.\s*decode)\s*\(", 24, "obfuscated_execution", S,
       "Executes decoded data (exec(base64/zlib/marshal...))", "python", "raw",
       ("sink:eval", "decoder", "obf:strong"), "MEDIUM"),
    # ---------------------------------------------------------------- Perl / CGI
    _r("perl.sink.exec", r"(?<![\w$])(?:system|exec)\s*\(|\bqx\s*[{(/]|open\s*\(\s*\w+\s*,\s*['\"][^'\"]*\|",
       3, "sink", W, "Perl command execution", "perl", "raw", ("sink:exec",)),
    _r("perl.flow.direct",
       r"(?:\bsystem|\bexec|\bqx|`)[^;\n]{0,120}?(?:param\s*\(|\$ENV\s*\{\s*['\"]?QUERY_STRING)",
       45, "source_to_sink", D, "CGI request data passed directly to command execution", "perl", "raw",
       ("flow:direct", "sink:exec", "source"), "CRITICAL"),
]


_EXEC_NAMES = ("system", "exec", "passthru", "popen", "proc_open", "assert", "create_function")
_DECODERS = ("base64_decode", "gzinflate", "gzuncompress", "gzdecode", "str_rot13", "strrev",
             "convert_uudecode", "hex2bin", "urldecode")

# Literal prefilters: a rule's regex only runs when one of these (lowercase)
# substrings occurs in the text. This keeps large clean trees fast.
RULE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "php.sink.eval": ("eval",), "php.sink.assert": ("assert",),
    "php.sink.create_function": ("create_function",), "php.sink.system": ("system",),
    "php.sink.exec": ("exec",), "php.sink.shell_exec": ("shell_exec",),
    "php.sink.passthru": ("passthru",), "php.sink.popen": ("popen",),
    "php.sink.proc_open": ("proc_open",), "php.sink.pcntl_exec": ("pcntl_exec",),
    "php.sink.preg_replace_e": ("preg_replace",), "php.sink.include_var": (("include", "require"), ("$",)),
    "php.callback.dangerous_literal": (("call_user_func", "array_", "sort(", "register_", "forward_static", "iterator_apply", "ob_start", "set_error", "set_exception"), _EXEC_NAMES),
    "php.source.request": ("$_get", "$_post", "$_request"), "php.source.cookie": ("$_cookie",),
    "php.source.files": ("$_files",), "php.source.header": ("http_", "getallheaders", "request_headers"),
    "php.source.raw_input": ("php://input",),
    "php.decode.base64": ("base64_decode",), "php.decode.gzinflate": ("gzinflate",),
    "php.decode.gzuncompress": ("gzuncompress",), "php.decode.gzdecode": ("gzdecode",),
    "php.decode.rot13": ("str_rot13",), "php.decode.uudecode": ("convert_uudecode",),
    "php.decode.hex2bin": ("hex2bin",), "php.decode.pack_hex": ("pack",),
    "php.decode.strrev": ("strrev",), "php.decode.openssl": ("_decrypt",),
    "php.decode.urldecode": ("urldecode",), "php.obf.nested_decoders": _DECODERS,
    "php.obf.eval_decoded": ("eval", "assert", "create_function"), "php.obf.chr_chain": ("chr",),
    "php.obf.globals_indirection": ("${", "$globals"), "php.obf.varvar": ("$$", "${"),
    "php.obf.superglobal_split": ("'_", '"_'),
    "php.obf.reversed_name": ("metsys", "cexe", "urhtssap", "nepo", "tressa", "lave", "edoced_",
                              "etalfnizg", "31tor", "noitcnuf"),
    "php.obf.error_suppressed_exec": ("@",), "php.obf.goto_spaghetti": ("goto",),
    "php.shell.preamble": ("error_reporting", "display_errors"),
    "php.include.suspicious_target": (("include", "require"),
                                      ("://", "data:", "/tmp/", "/dev/shm", "/var/tmp", ".jp", ".png", ".gif",
                                       ".ico", ".bmp", ".svg", ".txt", ".log", ".css", ".dat", ".tmp")),
    "php.dropper.write_script": (("file_put_contents", "fopen", "copy", "rename", "move_uploaded_file",
                                  "symlink", "link("),
                                 (".php", ".phtml", ".pht", ".phar", ".inc", ".jsp", ".asp", "htaccess", "user.ini")),
    "php.dropper.self_copy": ("__file__",), "php.dropper.timestomp": ("touch",),
    "php.dropper.readonly_chmod": ("chmod",),
    "php.dropper.remote_fetch": (("://",), ("file_get_contents", "fopen", "curl_init", "copy")),
    "php.uploader.unrestricted": (("move_uploaded_file", "copy"), ("tmp_name",)),
    "php.extract_request": (("extract", "parse_str", "import_request_variables"), ("$_", "php://input")),
    "php.network.reverse_shell": ("fsockopen", "stream_socket_client", "socket_create", "socket_connect"),
    "php.daemon.immortal": ("ignore_user_abort",), "php.mail.spam_mailer": ("mailer",),
    "marker.filesman": ("files",), "marker.c99": ("c99",), "marker.r57": ("r57",),
    "marker.wso": ("wso", "default_action"), "marker.b374": ("b37",),
    "marker.indo_alfa": ("indox", "alfatea", "alfa_d", "mini"),
    "marker.weevely": ("$kh",), "marker.generic_title": ("<title",),
    "generic.reverse_shell": ("/dev/tcp", "/bin/", "bash", "mkfifo", "socat"),
    "generic.sensitive_files": ("/etc/", "/proc/self"),
    "jsp.sink.runtime_exec": ("getruntime",), "jsp.sink.processbuilder": ("processbuilder",),
    "jsp.sink.scriptengine": ("scriptengine", "getenginebyname"), "jsp.source.param": ("request",),
    "jsp.flow.direct": (("request",), ("exec", "processbuilder")), "jsp.memshell.defineclass": ("defineclass", "classloader"),
    "asp.sink.wscript": ("wscript", "shell.application"), "asp.sink.process": ("process",),
    "asp.source.request": ("request",), "asp.flow.eval_request": (("request",), ("eval", "execute")),
    "asp.flow.jscript_unsafe": ("unsafe",), "asp.loader.assembly_load": ("assembly",),
    "asp.flow.cmd_request": (("request",), ("cmd.exe", "/c")),
    "node.sink.child_process": ("child_process",), "node.sink.exec_sync": ("sync",),
    "node.sink.eval": ("eval", "new function", "runin"), "node.source.request": ("req.", "request."),
    "node.flow.direct": (("req.", "request."), ("exec", "spawn", "eval", "new function")), "node.obf.eval_buffer": ("buffer", "atob"),
    "py.sink.exec": ("os.", "subprocess", "pty"), "py.sink.eval": ("eval", "exec", "__import__"),
    "py.source.request": ("request",), "py.flow.direct": (("request",), ("os.", "subprocess", "eval", "exec")),
    "py.obf.exec_decoded": ("b64decode", "decompress", "marshal", "codecs"),
    "perl.sink.exec": ("system", "exec", "qx", "open"), "perl.flow.direct": (("param", "query_string"), ("system", "exec", "qx", "`")),
}


def _keyword_groups(rule_id: str) -> tuple[tuple[str, ...], ...]:
    kw = RULE_KEYWORDS.get(rule_id, ())
    if not kw:
        return ()
    if isinstance(kw[0], tuple):
        return tuple(kw)  # type: ignore[arg-type]
    return (tuple(kw),)  # type: ignore[arg-type]


def compile_rules(weight_overrides: dict[str, int] | None = None) -> list[Rule]:
    """Compile the rule table, applying per-rule weight overrides."""
    overrides = weight_overrides or {}
    out = []
    for rule in RULES:
        weight = int(overrides.get(rule.id, rule.weight))
        compiled = re.compile(rule.pattern, rule.flags)
        out.append(Rule(rule.id, rule.pattern, weight, rule.category, rule.strength,
                        rule.description, rule.languages, rule.view, rule.tags,
                        rule.min_severity, rule.flags, compiled, _keyword_groups(rule.id),
                        rule.global_call))
    return out


def rules_for(rules: list[Rule], language: str | None) -> list[Rule]:
    """Rules applicable to *language* (generic 'any' rules always apply)."""
    return [r for r in rules if ANY in r.languages or (language and language in r.languages)]


def apply_rules(
    rules: list[Rule],
    views: dict[str, str],
    index: LineIndex,
    max_evidence: int = 3,
    max_snippet: int = 160,
    snippets: bool = True,
    source_label: str | None = None,
) -> list[Indicator]:
    """Run *rules* over the prepared text views and return indicators."""
    out: list[Indicator] = []
    lowered: dict[str, str] = {}
    for rule in rules:
        text = views.get(rule.view) or views["raw"]
        assert rule.compiled is not None
        if rule.keywords:
            key = rule.view if rule.view in views else "raw"
            low = lowered.get(key)
            if low is None:
                low = lowered[key] = text.lower()
            if not all(any(k in low for k in group) for group in rule.keywords):
                continue
        evidence = []
        count = 0
        for m in rule.compiled.finditer(text):
            if rule.global_call and not is_global_call(text, m.start()):
                continue
            if rule.global_call and _is_definition(text, m.start()):
                continue
            count += 1
            if snippets and len(evidence) < max_evidence:
                evidence.append(snippet_at(index, m.start(), m.end(), max_snippet, source_label))
            if count >= 1000:
                break
        if count:
            desc = rule.description
            if source_label:
                desc = f"{desc} [{source_label}]"
            out.append(Indicator(
                rule_id=rule.id + (".decoded" if source_label else ""),
                category=rule.category,
                description=desc,
                weight=rule.weight,
                strength=rule.strength,
                evidence=evidence,
                occurrences=count,
                min_severity=rule.min_severity,
                tags=rule.tags,
            ))
    return out


def is_global_call(text: str, pos: int) -> bool:
    """True unless the identifier at *pos* continues a longer identifier,
    is a variable (``$exec``) or is a method/static call (``->exec``/``::exec``)."""
    if pos == 0:
        return True
    prev = text[pos - 1]
    if prev.isalnum() or prev in "_$":
        return False
    return text[max(0, pos - 2):pos] not in ("->", "::")


def _is_definition(text: str, pos: int) -> bool:
    """True when the match at *pos* is a function definition, not a call."""
    before = text[max(0, pos - 24):pos]
    return bool(re.search(r"function\s*&?\s*$", before))
