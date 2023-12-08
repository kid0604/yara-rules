rule Unspecified_Malware_Oct16_C
{
	meta:
		description = "Detects an unspecififed malware - October 2016"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-10-08"
		score = 80
		hash1 = "a451157f75627b2fef3d663946c94ef7dacb58f08b31d0ec4c0a542a1c4e6205"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "dUSER32.DLL" fullword wide
		$s2 = "output.dll" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <5000KB and all of them )
}
