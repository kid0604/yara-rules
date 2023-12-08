rule Dorkbot_Injector_Malware
{
	meta:
		description = "Detects Darkbot Injector"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-10-08"
		hash1 = "bc3c5ac7180c8ac21d6908d747aa6122154d2bb51bb99ff0e0b1c65088d275dc"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Enter an integer, a real number, a character and a string : " fullword ascii
		$s2 = "ready to finish" fullword ascii
		$s3 = "EYEnpw" fullword ascii
		$s4 = "somewhere i belong" fullword ascii
		$s5 = "Not all fields were assigned" fullword ascii
		$s6 = "take down" fullword ascii
		$s7 = "real number = %f" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and 6 of them )
}
