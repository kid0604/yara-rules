import "pe"

rule Equation_Kaspersky_EOP_Package
{
	meta:
		description = "Equation Group Malware - EoP package and malware launcher"
		author = "Florian Roth"
		reference = "http://goo.gl/ivt8EW"
		date = "2015/02/16"
		hash = "2bd1b1f5b4384ce802d5d32d8c8fd3d1dc04b962"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$s0 = "abababababab" fullword ascii
		$s1 = "abcdefghijklmnopq" fullword ascii
		$s2 = "@STATIC" fullword wide
		$s3 = "$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" fullword ascii
		$s4 = "@prkMtx" fullword wide
		$s5 = "prkMtx" fullword wide
		$s6 = "cnFormVoidFBC" fullword wide

	condition:
		($mz at 0) and filesize <100000 and all of ($s*)
}
