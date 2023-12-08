rule EquationGroup_Toolset_Apr17_PacketScan_Implant
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "9b97cac66d73a9d268a15e47f84b3968b1f7d3d6b68302775d27b99a56fbb75a"
		os = "windows"
		filetype = "executable"

	strings:
		$op0 = { e9 ef fe ff ff ff b5 c0 ef ff ff 8d 85 c8 ef ff }
		$op1 = { c9 c2 04 00 b8 34 26 00 68 e8 40 05 00 00 51 56 }
		$op2 = { e9 0b ff ff ff 8b 45 10 8d 4d c0 89 58 08 c6 45 }

	condition:
		( uint16(0)==0x5a4d and filesize <30KB and all of them )
}
