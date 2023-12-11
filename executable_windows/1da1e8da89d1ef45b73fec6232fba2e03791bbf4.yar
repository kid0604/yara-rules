rule EquationGroup_Toolset_Apr17_DiBa_Target_alt_1
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "ffff3526ed0d550108e97284523566392af8523bbddb5f212df12ef61eaad3e6"
		os = "windows"
		filetype = "executable"

	strings:
		$op1 = { 41 5a 41 59 41 58 5f 5e 5d 5a 59 5b 58 48 83 c4 }
		$op2 = { f9 48 03 fa 48 33 c0 8a 01 49 03 c1 49 f7 e0 88 }
		$op3 = { 01 41 f6 e0 49 03 c1 88 01 48 33 }

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
