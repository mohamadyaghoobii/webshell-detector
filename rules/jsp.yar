/* Defensive YARA rules for JSP/Java web shells (webshell-hunter). */

rule jsp_request_to_runtime_exec
{
    meta:
        description = "JSP passing request parameters to Runtime.exec/ProcessBuilder"
        weight = 30
        strength = "definitive"
        min_severity = "CRITICAL"
        tags = "sink:exec,source,flow:direct"
    strings:
        $exec1 = /Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(/
        $exec2 = /new\s+ProcessBuilder\s*\(/
        $req = /request\s*\.\s*getParameter\s*\(/
    condition:
        ($exec1 or $exec2) and $req and filesize < 500KB
}

rule jsp_class_loader_from_encrypted_data
{
    meta:
        description = "Defines classes from decoded/decrypted bytes (memory-shell loader style)"
        weight = 22
        strength = "strong"
        min_severity = "HIGH"
        tags = "sink:eval,obf:strong"
    strings:
        $d1 = "defineClass" ascii
        $c1 = "javax.crypto.Cipher" ascii
        $b1 = /Base64\s*\.\s*getDecoder|BASE64Decoder|decodeBuffer/
        $r1 = /request\s*\.\s*(getReader|getInputStream|getParameter)/
    condition:
        $d1 and ($c1 or $b1) and $r1
}
