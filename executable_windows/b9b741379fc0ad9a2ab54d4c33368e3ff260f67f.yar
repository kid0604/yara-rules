import "pe"

rule MALWARE_Win_Gelsemine
{
	meta:
		author = "ditekSHen"
		description = "Detects Gelsemine"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "If any of these steps fails.only pick one of the targets for configuration\"If you want to just get on with it*which also use [ " wide
		$s2 = "A make implementation+with core modules (please read NOTES.PER_L)2The per_l Text::Template (please read NOTES.PER_L)" wide
		$s3 = "NOTES.VMS (OpenVMS)!NOTES.WIN (any supported Windows)%NOTES.DJGPP (DOS platform with DJGPP)'NOTES.ANDROID (obviously Android [ND" wide
		$s4 = "A simple example would be this)which is to be understood as one of these" fullword wide
		$s5 = "bala bala bala" fullword wide
		$s6 = "echo FOO" fullword wide
		$s7 = "?_Tidy@?$basic_string@DU?$char_traits@D@std@@V" ascii
		$o1 = { eb 08 c7 44 24 34 fd ff ff ff 8b 44 24 54 8b 4c }
		$o2 = { eb 08 c7 44 24 34 fd ff ff ff 8b 44 24 54 8b 4c }
		$o3 = { 8b 76 08 2b f0 a1 34 ff 40 00 03 f0 89 35 38 ff }
		$o4 = { 83 c4 34 c3 8b 4e 20 6a 05 e8 73 10 00 00 8b 76 }
		$o5 = { 8b 44 24 44 2b d1 03 d0 8b f2 e9 14 ff ff ff 8d }
		$o6 = { 68 00 06 00 00 6a 00 e8 d3 ff ff ff a2 48 00 41 }

	condition:
		uint16(0)==0x5a4d and (6 of ($s*) or ( all of ($o*) and 2 of ($s*)))
}
