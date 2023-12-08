rule EquationGroup_Toolset_Apr17_PC_Level3_Gen
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "c7dd49b98f399072c2619758455e8b11c6ee4694bb46b2b423fa89f39b185a97"
		hash2 = "f6b723ef985dfc23202870f56452581a08ecbce85daf8dc7db4491adaa4f6e8f"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "S-%u-%u" fullword ascii
		$s2 = "Copyright (C) Microsoft" fullword wide
		$op1 = { 24 39 65 c6 44 24 3a 6c c6 44 24 3b 65 c6 44 24 }
		$op2 = { 44 24 4e 41 88 5c 24 4f ff }
		$op3 = { 44 24 3f 6e c6 44 24 40 45 c6 44 24 41 }

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and 3 of them )
}
