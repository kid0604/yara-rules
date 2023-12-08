rule EquationGroup_Toolset_Apr17_PC_Level3_http_exe
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "3e855fbea28e012cd19b31f9d76a73a2df0eb03ba1cb5d22aafe9865150b020c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Copyright (C) Microsoft" fullword wide
		$op1 = { 24 39 65 c6 44 24 3a 6c c6 44 24 3b 65 c6 44 24 }
		$op2 = { 44 24 4e 41 88 5c 24 4f ff }
		$op3 = { 44 24 3f 6e c6 44 24 40 45 c6 44 24 41 }

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and all of them )
}
