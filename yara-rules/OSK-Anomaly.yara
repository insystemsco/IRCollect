import "pe"
rule osk_ANOMALY {
	meta: 
	Description: "Checks for OSK anomalies."

    strings:
        $upd_magic = { 44 43 } 
        $s1 = "Accessibility On-Screen Keyboard" wide fullword
        $s2 = "\\oskmenu" wide fullword
        $s3 = "&About On-Screen Keyboard..." wide fullword
        $s4 = "Software\\Microsoft\\Osk" wide 
    condition:
        filename matches /osk\.exe/is and not 1 of ($s*) and not ( $upd_magic at 0 )
}