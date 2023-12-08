rule EquationGroup_Toolset_Apr17_RemoteExecute_Implant
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "770663c07c519677316934cf482e500a73540d9933342c425f3e56258e6e6d8b"
		os = "windows"
		filetype = "executable"

	strings:
		$op1 = { 53 00 63 00 68 00 65 00 64 00 75 00 6C 00 65 00
               00 00 00 00 53 00 65 00 72 00 76 00 69 00 63 00
               65 00 73 00 41 00 63 00 74 00 69 00 76 00 65 00
               00 00 00 00 FF FF FF FF 00 00 00 00 B0 17 00 68
               5C 00 70 00 69 00 70 00 65 00 5C 00 53 00 65 00
               63 00 6F 00 6E 00 64 00 61 00 72 00 79 00 4C 00
               6F 00 67 00 6F 00 6E 00 00 00 00 00 5C 00 00 00
               57 00 69 00 6E 00 53 00 74 00 61 00 30 00 5C 00
               44 00 65 00 66 00 61 00 75 00 6C 00 74 00 00 00
               6E 00 63 00 61 00 63 00 6E 00 5F 00 6E 00 70 00
               00 00 00 00 5C 00 70 00 69 00 70 00 65 00 5C 00
               53 00 45 00 43 00 4C 00 4F 00 47 00 4F 00 4E }

	condition:
		( uint16(0)==0x5a4d and filesize <40KB and all of them )
}
