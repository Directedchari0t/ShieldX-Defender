rule Ransomware_Behavior {
    meta:
        description = "Detects ransomware patterns"
    strings:
        $encrypt_ext = /\.encrypted|\.locked|\.crypt/ 
        $ransom_note = "READ_ME_FOR_DECRYPT" wide
    condition:
        any of them
}
