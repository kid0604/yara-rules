rule EquationGroup_Toolset_Apr17_Mcl_NtMemory_Std
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "087db4f2dbf8e0679de421fec8fb2e6dd50625112eb232e4acc1408cc0bcd2d7"
		os = "windows"
		filetype = "executable"

	strings:
		$op1 = { 44 24 37 50 c6 44 24 38 72 c6 44 }
		$op2 = { 44 24 33 6f c6 44 24 34 77 c6 }
		$op3 = { 3b 65 c6 44 24 3c 73 c6 44 24 3d 73 c6 44 24 3e }

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
