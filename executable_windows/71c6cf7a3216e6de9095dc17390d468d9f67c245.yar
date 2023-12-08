import "pe"

rule WPR_loader_DLL
{
	meta:
		description = "Windows Password Recovery - file loader64.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-03-15"
		hash1 = "7b074cb99d45fc258e0324759ee970467e0f325e5d72c0b046c4142edc6776f6"
		hash2 = "a1f27f7fd0e03601a11b66d17cfacb202eacf34f94de3c4e9d9d39ea8d1a2612"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "loader64.dll" fullword ascii
		$x2 = "loader.dll" fullword ascii
		$s1 = "TUlDUk9TT0ZUX0FVVEhFTlRJQ0FUSU9OX1BBQ0tBR0VfVjFfMA==" fullword ascii
		$s2 = "UmVtb3RlRGVza3RvcEhlbHBBc3Npc3RhbnRBY2NvdW50" fullword ascii
		$s3 = "U2FtSVJldHJpZXZlUHJpbWFyeUNyZWRlbnRpYWxz" fullword ascii
		$s4 = "VFM6SW50ZXJuZXRDb25uZWN0b3JQc3dk" fullword ascii
		$s5 = "TCRVRUFjdG9yQWx0Q3JlZFByaXZhdGVLZXk=" fullword ascii
		$s6 = "YXNwbmV0X1dQX1BBU1NXT1JE" fullword ascii
		$s7 = "TCRBTk1fQ1JFREVOVElBTFM=" fullword ascii
		$s8 = "RGVmYXVsdFBhc3N3b3Jk" fullword ascii
		$op0 = { 48 8b cd e8 e0 e8 ff ff 48 89 07 48 85 c0 74 72 }
		$op1 = { e8 ba 23 00 00 33 c9 ff 15 3e 82 }
		$op2 = { 48 83 c4 28 e9 bc 55 ff ff 48 8d 0d 4d a7 00 00 }

	condition:
		uint16(0)==0x5a4d and filesize <400KB and ((1 of ($x*) and 1 of ($s*)) or (1 of ($s*) and all of ($op*)))
}
