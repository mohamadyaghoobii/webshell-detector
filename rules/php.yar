/*
   Defensive YARA rules for PHP web shells and loaders (webshell-hunter).

   Conventions
   - meta.weight / meta.strength / meta.min_severity feed the scanner's scoring.
   - Marker strings are written as regular expressions with a character class
     (e.g. /Files[M]an/) so this rule file does not itself contain the marker.
   - Rules describe characteristics; they contain no functional payloads.
*/

rule php_input_to_exec_sink
{
    meta:
        description = "Request input passed directly to a PHP command/eval function"
        weight = 30
        strength = "definitive"
        min_severity = "CRITICAL"
        tags = "sink:exec,source,flow:direct"
    strings:
        $php = "<?" ascii
        $re1 = /(system|passthru|shell_exec|exec|popen|proc_open|eval|assert)\s*\(\s*@?\s*(stripslashes\s*\(\s*)?\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/ nocase
    condition:
        $php and $re1
}

rule php_eval_of_decoder
{
    meta:
        description = "eval/assert of decoded data (base64/gzinflate/str_rot13 loader)"
        weight = 20
        strength = "strong"
        min_severity = "MEDIUM"
        tags = "sink:eval,decoder,obf:strong"
    strings:
        $php = "<?" ascii
        $re1 = /(eval|assert)\s*\(\s*@?\s*(gzinflate|gzuncompress|gzdecode|base64_decode|str_rot13|convert_uudecode|strrev)\s*\(/ nocase
    condition:
        $php and $re1
}

rule php_input_callable
{
    meta:
        description = "Function name taken from request input ($_POST['a']($_POST['b']))"
        weight = 30
        strength = "definitive"
        min_severity = "CRITICAL"
        tags = "sink:eval,source,dyn:strong"
    strings:
        $re1 = /\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        $re1
}

rule php_known_webshell_markers
{
    meta:
        description = "Strings characteristic of well-known PHP web shell families"
        weight = 25
        strength = "strong"
        min_severity = "MEDIUM"
        tags = "marker"
    strings:
        $m1 = /Files[M]an/
        $m2 = /c99[s]hell/ nocase
        $m3 = /r57[s]hell/ nocase
        $m4 = /b37[4]k/ nocase
        $m5 = /Indo[X]ploit/ nocase
        $m6 = /\$default_[a]ction\s*=\s*['"]Files/
    condition:
        any of them
}

rule php_code_in_image
{
    meta:
        description = "Image file (JPEG/PNG/GIF) containing a PHP open tag"
        weight = 25
        strength = "strong"
        min_severity = "MEDIUM"
        tags = "php_in_media,hidden_code"
    strings:
        $php = /<\?php[\s(\/]/ nocase
    condition:
        (uint16(0) == 0xD8FF or uint32(0) == 0x474E5089 or uint32(0) == 0x38464947) and $php
}

rule php_obfuscated_superglobal
{
    meta:
        description = "Superglobal name assembled from fragments or chr() codes"
        weight = 12
        strength = "strong"
        tags = "obf:strong"
    strings:
        $f1 = /['"]_P['"]\s*\.\s*['"]OST['"]/ nocase
        $f2 = /['"]_PO['"]\s*\.\s*['"]ST['"]/ nocase
        $f3 = /['"]_G['"]\s*\.\s*['"]ET['"]/ nocase
        $f4 = /['"]_REQ['"]\s*\.\s*['"]UEST['"]/ nocase
        $c1 = /chr\s*\(\s*95\s*\)\s*\.\s*chr\s*\(\s*80\s*\)/ nocase
    condition:
        any of them
}

rule php_self_respawning_loop
{
    meta:
        description = "ignore_user_abort + set_time_limit(0) + infinite loop writing files (re-infection loop)"
        weight = 18
        strength = "strong"
        tags = "respawn,dropper"
    strings:
        $a = /ignore_user_abort\s*\(\s*(1|true)\s*\)/ nocase
        $b = /set_time_limit\s*\(\s*0\s*\)/ nocase
        $c = /while\s*\(\s*(1|true)\s*\)/ nocase
        $d = /(file_put_contents|fwrite|copy)\s*\(/ nocase
    condition:
        all of them
}
