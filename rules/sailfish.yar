/*
 * Sailfish OS specific rules.
 *
 * Rules named Coastguard_Indicator_* are INDICATORS: they describe something
 * a package is able to do that deserves a look, and legitimate apps match
 * them too (a messaging app reads the message database). They are listed in
 * the report but do not change the verdict.
 *
 * Any other rule name counts as a detection and fails the scan. To promote
 * an indicator, rename it without the Coastguard_Indicator_ prefix.
 */

rule Coastguard_Indicator_Reads_Contacts_Database
{
    strings:
        $a = "qtcontacts-sqlite" ascii wide
        $b = "privileged/Contacts" ascii wide
    condition:
        any of them
}

rule Coastguard_Indicator_Reads_Messages_Or_Call_History
{
    strings:
        $a = "commhistory.db" ascii wide
        $b = ".local/share/commhistory" ascii wide
    condition:
        any of them
}

rule Coastguard_Indicator_Reads_Account_Credentials
{
    strings:
        $a = "libaccounts-glib/accounts.db" ascii wide
        $b = "signond/signon.db" ascii wide
        $c = "privileged/Accounts" ascii wide
        $d = "privileged/Secrets" ascii wide
        $e = "/etc/shadow" ascii wide
    condition:
        any of them
}

rule Coastguard_Indicator_Reads_Browser_Profile_Data
{
    strings:
        $dir1 = "org.sailfishos/browser" ascii wide
        $dir2 = ".mozilla/mozembed" ascii wide
        $file1 = "logins.json" ascii wide
        $file2 = "key4.db" ascii wide
        $file3 = "cookies.sqlite" ascii wide
    condition:
        any of ($dir*) and any of ($file*)
}

rule Coastguard_Indicator_Reads_Wifi_Passwords
{
    strings:
        $a = "/var/lib/connman" ascii wide
    condition:
        $a
}

rule Coastguard_Indicator_Reads_Email_Store
{
    strings:
        $a = "/.qmf/" ascii wide
    condition:
        $a
}

rule Coastguard_Indicator_Reads_Android_App_Data
{
    strings:
        $a = "/home/.android/data" ascii wide
        $b = "/home/.appsupport/" ascii wide
    condition:
        any of them
}

rule Coastguard_Indicator_Touches_SSH_Keys
{
    strings:
        $a = ".ssh/authorized_keys" ascii wide
        $b = ".ssh/id_rsa" ascii wide
        $c = ".ssh/id_ed25519" ascii wide
    condition:
        any of them
}

rule Coastguard_Indicator_Gains_Root_With_Devel_Su
{
    strings:
        $a = "devel-su " ascii wide
        $b = "/usr/bin/devel-su" ascii wide
    condition:
        any of them
}

rule Coastguard_Indicator_Edits_Sudoers
{
    strings:
        $a = "/etc/sudoers" ascii wide
        $b = "NOPASSWD" ascii wide
    condition:
        any of them
}

rule Coastguard_Indicator_Installs_Packages_At_Runtime
{
    strings:
        $a = "pkcon install" ascii wide
        $b = "pkcon -y install" ascii wide
        $c = /rpm (-[a-zA-Z]*[iU][a-zA-Z]*|--install|--upgrade) / ascii
        $d = /zypper (-n |--non-interactive )?(in|install) / ascii
        $e = "ssu ar " ascii wide
        $f = "ssu addrepo" ascii wide
    condition:
        any of them
}

rule Coastguard_Indicator_Downloads_And_Runs_Shell_Code
{
    strings:
        $pipe = /(curl|wget)[^\n|]{1,200}\|[ \t]*(sudo[ \t]+|devel-su[ \t]+)?(ba|da|a)?sh\b/ ascii
    condition:
        $pipe
}

rule Coastguard_Indicator_Reverse_Shell_Pattern
{
    strings:
        $a = "/dev/tcp/" ascii wide
        $b = /nc(at)? [^\n]{0,60}-e[ \t]+\/bin\/(ba)?sh/ ascii
        $c = /(ba)?sh -i[ \t]*>&/ ascii
        $d = "socat exec:" ascii nocase
    condition:
        any of them
}

rule Coastguard_Indicator_Installs_Persistence
{
    strings:
        $a = "/etc/systemd/system/" ascii wide
        $b = ".config/systemd/user/" ascii wide
        $c = "/etc/profile.d/" ascii wide
        $d = "/etc/xdg/autostart/" ascii wide
        $e = "/etc/ld.so.preload" ascii wide
    condition:
        any of them
}

rule Coastguard_Indicator_Sends_SMS_Or_Places_Calls
{
    strings:
        $sms = "org.ofono.MessageManager" ascii wide
        $call1 = "org.ofono.VoiceCallManager" ascii wide
        $call2 = "org.nemomobile.voicecall" ascii wide
    condition:
        any of them
}

rule Coastguard_Indicator_Reads_Raw_Input_Devices
{
    strings:
        $a = "/dev/input/event" ascii wide
        $b = "/dev/uinput" ascii wide
    condition:
        any of them
}

rule Coastguard_Indicator_Takes_Screenshots
{
    strings:
        $iface = "org.nemomobile.lipstick" ascii wide
        $call = "saveScreenshot" ascii wide
    condition:
        all of them
}

rule Coastguard_Indicator_Cryptocurrency_Mining
{
    strings:
        $a = "stratum+tcp://" ascii wide
        $b = "stratum+ssl://" ascii wide
        $c = "xmrig" ascii wide nocase
    condition:
        any of them
}

rule Coastguard_Indicator_Tampers_With_Other_Apps_Sandbox
{
    strings:
        $perm = "/etc/sailjail/permissions" ascii wide
        $apps = "/usr/share/applications/" ascii wide
        $edit = /sed[ \t]+-i/ ascii
        $off = "Sandboxing=Disabled" ascii wide
    condition:
        ($edit and ($perm or $apps)) or ($off and $apps and $edit)
}
