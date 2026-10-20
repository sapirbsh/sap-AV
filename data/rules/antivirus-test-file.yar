/*
    EICAR anti-virus test file.

    This file deliberately does NOT contain the full EICAR string (the project never commits it, and a real
    antivirus could quarantine this rule file). It matches the start and the end of the string instead,
    with the start at offset 0 and the file no larger than the 128 bytes the EICAR spec allows.
*/

rule EICAR_Test_File
{
    meta:
        description = "EICAR standard antivirus test file: a harmless file every antivirus detects, used to check that detection works"
        verdict = "malicious"
        mitre = "T1204.002"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"

    strings:
        $head = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
        $tail = "-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $head at 0 and $tail and filesize <= 128
}
