rule EquationGroup_Toolset_Apr17_put_Implant9x
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "8fcc98d63504bbacdeba0c1e8df82f7c4182febdf9b08c578d1195b72d7e3d5f"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "3&3.3<3A3F3K3V3c3m3" fullword ascii
		$op1 = { c9 c2 08 00 b8 72 1c 00 68 e8 c9 fb ff ff 51 56 }
		$op2 = { 40 1b c9 23 c8 03 c8 38 5d 14 74 05 6a 03 58 eb }

	condition:
		( uint16(0)==0x5a4d and filesize <20KB and 2 of them )
}
