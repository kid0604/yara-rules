rule EquationGroup_Toolset_Apr17_SetCallback_alt_1
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "a8854f6b01d0e49beeb2d09e9781a6837a0d18129380c6e1b1629bc7c13fdea2"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "*NOTE: This version of SetCallback does not work with PeddleCheap versions prior" fullword ascii
		$s3 = "USAGE: SetCallback <input file> <output file>" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and all of them )
}
