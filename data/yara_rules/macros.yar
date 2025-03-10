rule Office_Macros {
    meta:
        description = "Detects Office document macros"
    strings:
        $vba = "Sub AutoOpen()" nocase
        $ole = "d0cf11e0a1b11ae1"  // OLE header
    condition:
        any of them
}

rule Malicious_VBA {
    meta:
        description = "Detects suspicious VBA patterns"
    strings:
        $shell = "Shell(" nocase
        $cmd = "cmd.exe" nocase
    condition:
        any of them and Office_Macros
}
