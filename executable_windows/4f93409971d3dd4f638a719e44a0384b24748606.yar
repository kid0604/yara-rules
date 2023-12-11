rule Equation_Kaspersky_EOP_Package_alt_1
{
	meta:
		description = "Equation Group Malware - EoP package and malware launcher"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "2bd1b1f5b4384ce802d5d32d8c8fd3d1dc04b962"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "abababababab" fullword ascii
		$s1 = "abcdefghijklmnopq" fullword ascii
		$s2 = "@STATIC" fullword wide
		$s3 = "$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" fullword ascii
		$s4 = "@prkMtx" fullword wide
		$s5 = "prkMtx" fullword wide
		$s6 = "cnFormVoidFBC" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100000 and all of ($s*)
}
