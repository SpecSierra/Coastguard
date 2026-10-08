/*
 * Coastguard's own rules, loaded next to the YARA Forge core set.
 * Sailfish-specific rules belong here.
 */

rule Coastguard_EICAR_Test_Marker
{
    meta:
        description = "EICAR antivirus test marker; used by tests/selftest.sh to prove the YARA path detects"
    strings:
        $marker = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $marker
}
