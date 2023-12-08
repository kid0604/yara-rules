rule EquationGroup_Toolset_Apr17_PC_Legacy_dll
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "0cbc5cc2e24f25cb645fb57d6088bcfb893f9eb9f27f8851503a1b33378ff22d"
		os = "windows"
		filetype = "executable"

	strings:
		$op1 = { 45 f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 }
		$op2 = { 49 c6 45 e1 73 c6 45 e2 57 c6 45 e3 }
		$op3 = { 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 6f c6 45 ea }

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and all of them )
}
