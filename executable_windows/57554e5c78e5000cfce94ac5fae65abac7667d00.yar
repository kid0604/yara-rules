rule EquationGroup_Toolset_Apr17_KisuComms_Target_2000
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "94eea1bad534a1dc20620919de8046c9966be3dd353a50f25b719c3662f22135"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "363<3S3c3l3q3v3{3" fullword ascii
		$s2 = "3!3%3)3-3135393@5" fullword ascii
		$op0 = { eb 03 89 46 54 47 83 ff 1a 0f 8c 40 ff ff ff 8b }
		$op1 = { 8b 46 04 85 c0 74 0f 50 e8 34 fb ff ff 83 66 04 }
		$op2 = { c6 45 fc 02 8d 8d 44 ff ff ff e8 d2 2f 00 00 eb }

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and ( all of ($s*) or all of ($op*)))
}
