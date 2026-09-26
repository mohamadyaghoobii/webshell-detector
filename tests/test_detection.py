"""Content detection: signatures, source-to-sink, obfuscation, locations."""

from __future__ import annotations

import base64
import os
import random
import zlib

from tests.conftest import (B64D, COOKIE, EVAL, GET, GZI, POST, REQUEST, SHELL_EXEC, SYS, php, rules,
                            scan, write)


def test_clean_php_is_not_reported(webroot):
    write(webroot, "index.php", php(
        "$name = htmlspecialchars($_GET['name'] ?? 'world');\n"
        "echo 'Hello ' . $name;\n"
        "include __DIR__ . '/lib/helpers.php';\n"
        "$rows = $pdo->exec('DELETE FROM sessions WHERE expired = 1');\n"))
    write(webroot, "lib/helpers.php", php("function greet($n) { return strtoupper($n); }"))
    result, by = scan(webroot)
    assert by["index.php"].severity in ("INFO",)
    assert all(f.severity in ("INFO",) for f in result.findings)


def test_system_get_cmd_is_critical(webroot):
    write(webroot, "tool.php", php(f"{SYS}({GET}['cmd']);"))
    _, by = scan(webroot)
    f = by["tool.php"]
    assert f.severity == "CRITICAL"
    assert f.confidence == "VERY_HIGH"
    assert "php.flow.exec_direct" in rules(f)
    ev = [e for i in f.indicators if i.rule_id == "php.flow.exec_direct" for e in i.evidence]
    assert ev and ev[0].line == 3


def test_indirect_flow_through_variable(webroot):
    write(webroot, "a.php", php(f"$c = {POST}['c'];\n$d = trim($c);\n{SHELL_EXEC}($d);"))
    _, by = scan(webroot)
    assert "php.flow.exec_indirect" in rules(by["a.php"])
    assert by["a.php"].severity in ("HIGH", "CRITICAL")


def test_sanitized_flow_is_downgraded(webroot):
    write(webroot, "convert.php", php(f"{SYS}('convert ' . escapeshellarg({GET}['f']));"))
    _, by = scan(webroot)
    f = by["convert.php"]
    assert "php.flow.exec_sanitized" in rules(f)
    assert f.severity not in ("HIGH", "CRITICAL")


def test_eval_base64_loader(webroot):
    blob = base64.b64encode(b"echo 'inert';" * 40).decode()
    write(webroot, "loader.php", php(f"{EVAL}({B64D}('{blob}'));"))
    _, by = scan(webroot)
    f = by["loader.php"]
    assert "php.obf.eval_decoded" in rules(f)
    assert f.severity in ("HIGH", "CRITICAL")


def test_decoded_layer_reveals_flow(webroot):
    inner = f"{SYS}({REQUEST}['x']);".encode()
    packed = base64.b64encode(zlib.compress(inner)[2:-4]).decode()
    write(webroot, "packed.php", php(f"{EVAL}({GZI}({B64D}('{packed}')));"))
    _, by = scan(webroot)
    f = by["packed.php"]
    assert "php.flow.exec_direct.decoded" in rules(f)
    assert f.severity == "CRITICAL"


def test_dynamic_function_from_concatenation(webroot):
    write(webroot, "d.php", php(f'$f = "sy"."st"."em";\n$f({POST}["x"]);'))
    _, by = scan(webroot)
    r = rules(by["d.php"])
    assert "php.dyn.resolved_call_input" in r
    assert "php.obf.constructed_name" in r
    assert by["d.php"].severity == "CRITICAL"


def test_dynamic_function_from_base64_name(webroot):
    name = base64.b64encode(SYS.encode()).decode()
    write(webroot, "e.php", php(f'$a = {B64D}("{name}");\n$a($input);'))
    _, by = scan(webroot)
    assert "php.dyn.resolved_call" in rules(by["e.php"])
    assert by["e.php"].severity in ("MEDIUM", "HIGH", "CRITICAL")


def test_function_name_from_cookie(webroot):
    write(webroot, "c.php", php(f"{COOKIE}['a']({COOKIE}['b']);"))
    _, by = scan(webroot)
    assert "php.dyn.input_callable" in rules(by["c.php"])
    assert by["c.php"].severity == "CRITICAL"


def test_globals_indirection(webroot):
    write(webroot, "g.php", php('${"GLOBALS"}["x"] = 1; $GLOBALS["fn"]($v);'))
    _, by = scan(webroot)
    assert "php.obf.globals_indirection" in rules(by["g.php"])


def test_array_index_lookup_is_not_taint(webroot):
    write(webroot, "router.php", php(
        f"$handlers = ['a' => 'show_a'];\n$k = {GET}['page'];\ncall_user_func($handlers[$k]);"))
    _, by = scan(webroot)
    assert not any(r.startswith("php.flow.callback") for r in rules(by["router.php"]))


def test_php_inside_jpg(webroot):
    write(webroot, "images/avatar.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 64 +
          ("<?php " + f"{EVAL}({POST}['x']); ?>").encode())
    _, by = scan(webroot)
    f = by["images/avatar.jpg"]
    assert "mismatch.php_in_media" in rules(f)
    assert f.severity == "CRITICAL"


def test_random_binary_image_is_clean(webroot):
    rnd = random.Random(1)
    write(webroot, "images/photo.png", b"\x89PNG\r\n\x1a\n" + bytes(rnd.randrange(256) for _ in range(200000)))
    _, by = scan(webroot)
    assert "images/photo.png" not in by or by["images/photo.png"].severity == "INFO"


def test_double_extension(webroot):
    write(webroot, "files/report.pdf.php", php("echo 1;"))
    _, by = scan(webroot)
    f = by["files/report.pdf.php"]
    assert "name.double_extension" in rules(f)
    assert f.severity in ("MEDIUM", "HIGH", "CRITICAL")


def test_dotted_library_name_is_weak(webroot):
    write(webroot, "lib/module.graphic.jpg.php", php("class X {}"))
    _, by = scan(webroot)
    assert "name.double_extension" not in rules(by["lib/module.graphic.jpg.php"])


def test_high_entropy_script(webroot):
    rnd = random.Random(7)
    blob = base64.b64encode(bytes(rnd.randrange(256) for _ in range(6000))).decode()
    write(webroot, "blob.php", php(f"$d = '{blob}';"))
    _, by = scan(webroot)
    r = rules(by["blob.php"])
    assert "shape.high_entropy" in r
    assert "shape.base64_blob" in r


def test_script_in_upload_directory(webroot):
    write(webroot, "uploads/avatar.php", php("echo 1;"))
    _, by = scan(webroot)
    assert "location.upload_dir" in rules(by["uploads/avatar.php"])


def test_upload_script_with_exec_is_high(webroot):
    write(webroot, "media/test.php", php(f"{SYS}('uptime');"))
    _, by = scan(webroot)
    assert by["media/test.php"].severity in ("HIGH", "CRITICAL")


def test_code_namespace_directory_not_upload(webroot):
    for i in range(6):
        write(webroot, f"src/Image/Class{i}.php", php(f"class C{i} {{}}"))
    _, by = scan(webroot)
    assert "location.upload_dir" not in rules(by["src/Image/Class0.php"])


def test_hidden_script(webroot):
    write(webroot, "wp-content/uploads/.cache.php", php(f"{SYS}({GET}['c']);"))
    write(webroot, "wp-config.php", php("define('DB_NAME', 'x');"))
    write(webroot, "wp-includes/version.php", php("$wp_version = '6.5';"))
    _, by = scan(webroot)
    f = by["wp-content/uploads/.cache.php"]
    r = rules(f)
    assert {"name.hidden_script", "location.framework_upload"} <= r
    assert f.severity == "CRITICAL"


def test_world_writable_script(webroot):
    p = write(webroot, "index.php", php("echo 1;"))
    os.chmod(p, 0o666)
    _, by = scan(webroot)
    f = by["index.php"]
    assert "meta.world_writable" in rules(f)
    assert f.severity == "LOW"


def test_known_marker_in_raw_text(webroot):
    write(webroot, "x.php", php("$default_" + "action = 'Files" + "Man';"))
    _, by = scan(webroot)
    assert "marker.wso" in rules(by["x.php"]) or "marker.filesman" in rules(by["x.php"])


def test_jsp_request_to_exec(webroot):
    write(webroot, "a.jsp", '<%@ page import="java.io.*" %><% Runtime.getRuntime().exec('
          'request.getParameter("c")); %>')
    _, by = scan(webroot)
    assert "jsp.flow.direct" in rules(by["a.jsp"])
    assert by["a.jsp"].severity == "CRITICAL"


def test_aspx_eval_request(webroot):
    write(webroot, "a.aspx", '<%@ Page Language="Jscript"%><% eval(Request.Item["z"],"unsafe"); %>')
    _, by = scan(webroot)
    assert by["a.aspx"].severity == "CRITICAL"


def test_evidence_is_capped_and_sanitised(webroot):
    blob = "A" * 300
    write(webroot, "s.php", php(f"$password = 'hunter2secret'; {SYS}({GET}['c']); $x='{blob}';\x01"))
    _, by = scan(webroot)
    snippets = [e.snippet for i in by["s.php"].indicators for e in i.evidence]
    assert all(len(s) <= 170 for s in snippets)
    assert not any("hunter2secret" in s for s in snippets)
