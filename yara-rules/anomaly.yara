rule iexplore_ANOMALY {
    strings:
        $upd_magic = { 44 43 }
        $win2003_win7_u1 = "IEXPLORE.EXE" wide nocase
        $win2003_win7_u2 = "Internet Explorer" wide fullword
        $win2003_win7_u3 = "translation" wide fullword nocase
        $win2003_win7_u4 = "varfileinfo" wide fullword nocase
    condition:
        not ( $upd_magic at 0 ) and not 1 of ($win*) and filename matches /iexplore\.exe/is
}

rule svchost_ANOMALY {
    strings:
        $upd_magic = { 44 43 }
        $win2003_win7_u1 = "svchost.exe" wide nocase
        $win2003_win7_u3 = "coinitializesecurityparam" wide fullword nocase
        $win2003_win7_u4 = "servicedllunloadonstop" wide fullword nocase
        $win2000 = "Generic Host Process for Win32 Services" wide fullword
        $win2012 = "Host Process for Windows Services" wide fullword   
    condition:
        filename matches /svchost\.exe/is and not 1 of ($win*) and not ( $upd_magic at 0 )
}

rule explorer_ANOMALY {

    strings:
        $upd_magic = { 44 43 }
        $s1 = "EXPLORER.EXE" wide fullword
        $s2 = "Windows Explorer" wide fullword 
    condition:
        filename matches /explorer\.exe/is and not 1 of ($s*) and not ( $upd_magic at 0 )
}

rule sethc_ANOMALY {

    strings:
        $upd_magic = { 44 43 }
        $s1 = "stickykeys" fullword nocase
        $s2 = "stickykeys" wide nocase
        $s3 = "Control_RunDLL access.cpl" wide fullword
        $s4 = "SETHC.EXE" wide fullword
    condition:
        filename matches /sethc\.exe/ and not 1 of ($s*) and not ( $upd_magic at 0 )
}

rule Utilman_ANOMALY {

    strings:
        $upd_magic = { 44 43 }
        $win7 = "utilman.exe" wide fullword
        $win2000 = "Start with Utility Manager" fullword wide
        $win2012 = "utilman2.exe" fullword wide
    condition:
        filename matches /utilman\.exe/is and not 1 of ($win*) and not ( $upd_magic at 0 )
}

rule osk_ANOMALY {

    strings:
        $upd_magic = { 44 43 } 
        $s1 = "Accessibility On-Screen Keyboard" wide fullword
        $s2 = "\\oskmenu" wide fullword
        $s3 = "&About On-Screen Keyboard..." wide fullword
        $s4 = "Software\\Microsoft\\Osk" wide 
    condition:
        filename matches /osk\.exe/is and not 1 of ($s*) and not ( $upd_magic at 0 )
}

rule magnify_ANOMALY {

    strings:
        $upd_magic = { 44 43 }
        $win7 = "Microsoft Screen Magnifier" wide fullword
        $win2000 = "Microsoft Magnifier" wide fullword
        $winxp = "Software\\Microsoft\\Magnify" wide   
    condition:
        filename matches /magnify\.exe/is and not 1 of ($win*) and not ( $upd_magic at 0 )
}

rule narrator_ANOMALY {

    strings:
        $upd_magic = { 44 43 }
        $win7 = "Microsoft-Windows-Narrator" wide fullword
        $win2000 = "&About Narrator..." wide fullword
        $win2012 = "Screen Reader" wide fullword
        $winxp = "Software\\Microsoft\\Narrator"
        $winxp_en = "SOFTWARE\\Microsoft\\Speech\\Voices" wide
    condition:
        filename matches /narrator\.exe/is and not 1 of ($win*) and not ( $upd_magic at 0 )
}

rule notepad_ANOMALY {

    strings:
        $upd_magic = { 44 43 }
        $win7 = "HELP_ENTRY_ID_NOTEPAD_HELP" wide fullword
        $win2000 = "Do you want to create a new file?" wide fullword
        $win2003 = "Do you want to save the changes?" wide
        $winxp = "Software\\Microsoft\\Notepad" wide   
    condition:
        filename matches /notepad\.exe/is and not 1 of ($win*) and not ( $upd_magic at 0 )
}
rule control_ANOMALY{
strings:
$s1 = "stickykeys" fullword nocase
$s2 = "stickykeys" wide nocase
$s3 = "Control_RunDLL access.cpl" wide
$s4 = "SETHC.EXE" wide
$filename = "filename: sethc.exe"

condition: $filename and not 1 of ($s*)
}
rule WMI_access
{
    strings:
        $ = /(root|ROOT)[\/\\](cimv|CIMV)2/ wide ascii
    condition:
        uint16(0) == 0x5a4d and any of them
}
rule IsNTAdmin {
    meta:
        reference = "http://www.sgr.info/dev/win32api/IsNTAdmin.htm"
    strings:
        $ = "advpack.dll\x00IsNTAdmin" wide ascii
    condition:
        uint16(0) == 0x5a4d and any of them
}
rule fxsst_dll
{
meta:
    reference = "https://www.fireeye.com/blog/threat-research/2011/06/fxsst.html"
strings:
    $f = "fxsst.dll" fullword wide ascii
condition:
    uint16(0) == 0x5a4d and any of them
}

rule ntshrui_dll
{
meta:
    reference = "https://www.mandiant.com/blog/malware-persistence-windows-registry/"
strings:
    $n = "ntshrui.dll" fullword wide ascii
condition:
    uint16(0) == 0x5a4d and any of them
}
rule pstore_access
{
strings:
    $ = "pstorec.dll" wide ascii
    $ = "PStoreCreateInstance" wide ascii
condition:
    uint16(0) == 0x5a4d and 2 of them
}
rule SuppressIldasmAttribute
{
strings:
    $ = "SuppressIldasmAttribute" wide ascii
condition:
    uint16(0) == 0x5a4d and any of them
}