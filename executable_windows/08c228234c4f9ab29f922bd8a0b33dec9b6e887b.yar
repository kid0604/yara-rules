rule EquationGroup_Toolset_Apr17_Windows_Implant
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "d38ce396926e45781daecd18670316defe3caf975a3062470a87c1d181a61374"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "0#0)0/050;0M0Y0h0|0" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <50KB and all of them )
}
