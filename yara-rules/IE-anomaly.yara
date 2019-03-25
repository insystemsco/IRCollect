import "pe"
rule iexplore_ANOMALY {
	meta: 
	Descriptions: "Checks Internet Explorer Anomalies"
    strings:
        $upd_magic = { 44 43 }
        $win2003_win7_u1 = "IEXPLORE.EXE" wide nocase
        $win2003_win7_u2 = "Internet Explorer" wide fullword
        $win2003_win7_u3 = "translation" wide fullword nocase
        $win2003_win7_u4 = "varfileinfo" wide fullword nocase
    condition:
        not ( $upd_magic at 0 ) and not 1 of ($win*) and filename matches /iexplore\.exe/is
}