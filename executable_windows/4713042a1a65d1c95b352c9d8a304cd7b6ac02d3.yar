rule EquationGroup_Toolset_Apr17_DmGz_Target_2
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "55ac29b9a67e0324044dafaba27a7f01ca3d8e4d8e020259025195abe42aa904"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\\\.\\%ls" fullword ascii
		$op0 = { e8 ce 34 00 00 b8 02 00 00 f0 e9 26 02 00 00 48 }
		$op1 = { 8b 4d 28 e8 02 05 00 00 89 45 34 eb 07 c7 45 34 }
		$op2 = { e8 c2 34 00 00 90 48 8d 8c 24 00 01 00 00 e8 a4 }

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}
