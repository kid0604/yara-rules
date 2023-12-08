rule APT_Project_Sauron_Custom_M7
{
	meta:
		description = "Detects malware from Project Sauron APT"
		author = "FLorian Roth"
		reference = "https://goo.gl/eFoP4A"
		date = "2016-08-09"
		hash1 = "6c8c93069831a1b60279d2b316fd36bffa0d4c407068dbef81b8e2fe8fd8e8cd"
		hash2 = "7cc0bf547e78c8aaf408495ceef58fa706e6b5d44441fefdce09d9f06398c0ca"
		os = "windows"
		filetype = "executable"

	strings:
		$sx1 = "Default user" fullword wide
		$sx2 = "Hincorrect header check" fullword ascii
		$sa1 = "MSAOSSPC.dll" fullword ascii
		$sa2 = "MSAOSSPC.DLL" fullword wide
		$sa3 = "MSAOSSPC" fullword wide
		$sa4 = "AOL Security Package" fullword wide
		$sa5 = "AOL Security Package" fullword wide
		$sa6 = "AOL Client for 32 bit platforms" fullword wide
		$op0 = { 8b ce 5b e9 4b ff ff ff 55 8b ec 51 53 8b 5d 08 }
		$op1 = { e8 0a fe ff ff 8b 4d 14 89 46 04 89 41 04 8b 45 }
		$op2 = { e9 29 ff ff ff 83 7d fc 00 0f 84 cf 0a 00 00 8b }
		$op3 = { 83 f8 0c 0f 85 3a 01 00 00 44 2b 41 6c 41 8b c9 }
		$op4 = { 44 39 57 0c 0f 84 d6 0c 00 00 44 89 6f 18 45 89 }
		$op5 = { c1 ed 02 83 c6 fe e9 68 fe ff ff 44 39 57 08 75 }

	condition:
		uint16(0)==0x5a4d and filesize <200KB and ((3 of ($s*) and 3 of ($op*)) or (1 of ($sx*) and 1 of ($sa*)))
}
