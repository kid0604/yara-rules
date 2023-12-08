rule APT_Project_Sauron_Custom_M6
{
	meta:
		description = "Detects malware from Project Sauron APT"
		author = "FLorian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-09"
		hash1 = "3782b63d7f6f688a5ccb1b72be89a6a98bb722218c9f22402709af97a41973c8"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "rseceng.dll" fullword wide
		$s2 = "Remote Security Engine" fullword wide
		$op0 = { 8b 0d d5 1d 00 00 85 c9 0f 8e a2 }
		$op1 = { 80 75 6e 85 c0 79 6a 66 41 83 38 0a 75 63 0f b7 }
		$op2 = { 80 75 29 85 c9 79 25 b9 01 }

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and ( all of ($s*)) and 1 of ($op*)) or ( all of them )
}
