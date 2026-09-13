rule Suspicious_PE_Header
{
    meta:
        description = "Detects suspicious PE file characteristics"
        author = "Mutiny"
    strings:
        $mz = { 4D 5A }
        $upx = "UPX0" ascii
        $upx1 = "UPX1" ascii
    condition:
        $mz at 0 and ($upx or $upx1)
}

rule Executable_In_Download
{
    meta:
        description = "Detects executable files commonly used for malware delivery"
        severity = "medium"
    strings:
        $mz = { 4D 5A }
        $ext1 = ".exe" ascii nocase
        $ext2 = ".scr" ascii nocase
        $ext3 = ".bat" ascii nocase
        $ext4 = ".cmd" ascii nocase
        $ext5 = ".ps1" ascii nocase
        $ext6 = ".vbs" ascii nocase
        $ext7 = ".js" ascii nocase
        $ext8 = ".wsf" ascii nocase
    condition:
        $mz at 0 and any of ($ext*)
}

rule Known_Malicious_Pattern
{
    meta:
        description = "Placeholder for known malicious byte patterns"
        severity = "high"
    strings:
        $shellcode = { FC E8 89 00 00 00 60 89 E5 }
    condition:
        $shellcode
}

rule EICAR_Test_File
{
    meta:
        description = "EICAR standard antivirus test file — a safe way to verify scanning"
        severity = "info"
    strings:
        $e = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR" ascii
    condition:
        $e
}
