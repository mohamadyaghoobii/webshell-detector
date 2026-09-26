/* Defensive YARA rules for ASP/ASPX web shells (webshell-hunter). */

rule asp_eval_request
{
    meta:
        description = "Classic ASP/ASPX evaluating request data (eval/Execute(Request(...)))"
        weight = 30
        strength = "definitive"
        min_severity = "CRITICAL"
        tags = "sink:eval,source,flow:direct"
    strings:
        $re1 = /\b(eval|execute|executeglobal)\s*\(?\s*request\s*(\.|\(|\[)/ nocase
        $re2 = /eval\s*\([^;]{0,120},\s*"unsafe"\s*\)/ nocase
    condition:
        any of them
}

rule aspx_cmd_process_with_request
{
    meta:
        description = "ASPX starting cmd.exe / Process with request-controlled arguments"
        weight = 22
        strength = "strong"
        min_severity = "HIGH"
        tags = "sink:exec,source"
    strings:
        $p1 = "ProcessStartInfo" ascii nocase
        $p2 = /Process\s*\.\s*Start\s*\(/ nocase
        $cmd = "cmd.exe" ascii nocase
        $req = /Request\s*(\.\s*(Form|QueryString|Item)|\s*\[|\s*\()/ nocase
    condition:
        ($p1 or $p2) and $cmd and $req
}

rule aspx_assembly_load_base64
{
    meta:
        description = "Loads a .NET assembly from Base64/decrypted data"
        weight = 22
        strength = "strong"
        min_severity = "HIGH"
        tags = "sink:eval,obf:strong"
    strings:
        $re1 = /Assembly\s*\.\s*Load\s*\([^)]{0,200}(FromBase64String|TransformFinalBlock|Decrypt)/ nocase
    condition:
        $re1
}
