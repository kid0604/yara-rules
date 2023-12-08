rule EquationGroup_Toolset_Apr17_Oracle_Implant
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "8e9be4960c62ed7f210ce08f291e410ce0929cd3a86fe70315d7222e3df4587e"
		os = "windows"
		filetype = "executable"

	strings:
		$op0 = { fe ff ff ff 48 89 9c 24 80 21 00 00 48 89 ac 24 }
		$op1 = { e9 34 11 00 00 b8 3e 01 00 00 e9 2a 11 00 00 b8 }
		$op2 = { 48 8b ca e8 bf 84 00 00 4c 8b e0 8d 34 00 44 8d }

	condition:
		( uint16(0)==0x5a4d and filesize <500KB and all of them )
}
