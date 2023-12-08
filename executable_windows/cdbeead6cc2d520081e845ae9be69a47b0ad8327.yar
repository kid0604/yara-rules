rule EquationGroup_Toolset_Apr17_SetPorts
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "722d3cf03908629bc947c4cca7ce3d6b80590a04616f9df8f05c02de2d482fb2"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "USAGE: SetPorts <input file> <output file> <version> <port1> [port2] [port3] [port4] [port5]" fullword ascii
		$s2 = "Valid versions are:  1 = PC 1.2   2 = PC 1.2 (24 hour)" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}
