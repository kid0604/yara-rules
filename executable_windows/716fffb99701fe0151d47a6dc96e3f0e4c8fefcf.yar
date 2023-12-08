rule EquationGroup_Toolset_Apr17_DiBa_Target_2000
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "f9ea8ff5985b94f635d03f3aab9ad4fb4e8c2ad931137dba4f8ee8a809421b91"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "0M1U1Z1p1" fullword ascii
		$op1 = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 }
		$op2 = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 }
		$op3 = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f }

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and 3 of them )
}
