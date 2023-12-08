rule EquationGroup_Toolset_Apr17_Banner_Implant9x
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "5d69a8cfc9b636448f023fcf18d111f13a8e6bcb9a693eb96276e0d796ab4e0c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = ".?AVFeFinallyFailure@@" fullword ascii
		$op1 = { c9 c3 57 8d 85 2c eb ff ff }

	condition:
		( uint16(0)==0x5a4d and filesize <20KB and all of them )
}
