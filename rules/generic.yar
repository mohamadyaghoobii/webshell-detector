/* Generic defensive YARA rules (webshell-hunter). */

rule generic_reverse_shell_strings
{
    meta:
        description = "Reverse-shell command strings (bash -i / /dev/tcp / nc -e)"
        weight = 18
        strength = "strong"
        min_severity = "HIGH"
        tags = "reverse_shell"
    strings:
        $a = /\/dev\/tcp\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,5}/
        $b = /bash\s+-i\s+>&/
        $c = /\bnc(at)?\s+(-[a-z]+\s+)*-e\s+\/bin\/(ba)?sh/
    condition:
        any of them
}

rule generic_download_and_execute
{
    meta:
        description = "Downloads content and pipes it to an interpreter (curl|sh)"
        weight = 15
        strength = "strong"
        tags = "dropper"
    strings:
        $a = /(curl|wget)\s[^\n|]{1,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b/
        $b = /(curl|wget)\s[^\n|]{1,200}\|\s*(python[0-9.]*|perl|php)\b/
    condition:
        any of them
}

rule generic_htaccess_image_as_php
{
    meta:
        description = ".htaccess / config mapping image or text extensions to the PHP handler"
        weight = 20
        strength = "strong"
        min_severity = "HIGH"
        tags = "config:handler"
    strings:
        $a = /(AddType|AddHandler)\s+[^\n]*(x-httpd-php|php[0-9]?-script)[^\n]*\.(jpe?g|png|gif|ico|txt)\b/ nocase
    condition:
        $a
}
