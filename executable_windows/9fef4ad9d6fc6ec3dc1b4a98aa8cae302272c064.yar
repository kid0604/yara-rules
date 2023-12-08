rule EquationGroup_Toolset_Apr17_drivers_Implant
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "ee8b048f1c6ba821d92c15d614c2d937c32aeda7b7ea0943fd4f640b57b1c1ab"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = ".?AVFeFinallyFailure@@" fullword ascii
		$s2 = "hZwLoadDriver" fullword ascii
		$op1 = { b0 01 e8 58 04 00 00 c3 33 }

	condition:
		( uint16(0)==0x5a4d and filesize <30KB and all of them )
}
