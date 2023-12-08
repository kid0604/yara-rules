rule APT_Project_Sauron_Custom_M2
{
	meta:
		description = "Detects malware from Project Sauron APT"
		author = "FLorian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-09"
		hash1 = "30a824155603c2e9d8bfd3adab8660e826d7e0681e28e46d102706a03e23e3a8"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "\\*\\3vpn" fullword ascii
		$op0 = { 55 8b ec 83 ec 0c 53 56 33 f6 39 75 08 57 89 75 }
		$op1 = { 59 59 c3 8b 65 e8 ff 75 88 ff 15 50 20 40 00 ff }
		$op2 = { 8b 4f 06 85 c9 74 14 83 f9 12 0f 82 a7 }

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and ( all of ($s*)) and all of ($op*))
}
