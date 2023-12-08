rule EquationGroup_Toolset_Apr17_msgks_mskgu
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "7b4986aee8f5c4dca255431902907b36408f528f6c0f7d7fa21f079fa0a42e09"
		hash2 = "ef906b8a8ad9dca7407e0a467b32d7f7cf32814210964be2bfb5b0e6d2ca1998"
		os = "windows"
		filetype = "executable"

	strings:
		$op1 = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 }
		$op2 = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 }
		$op3 = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f }

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
