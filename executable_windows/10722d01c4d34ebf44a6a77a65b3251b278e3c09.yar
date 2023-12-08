import "pe"

rule INDICATOR_EXE_Packed_RLPack
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with RLPACK"
		snort2_sid = "930064-930066"
		snort3_sid = "930023"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = ".packed" fullword ascii
		$s2 = ".RLPack" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them or for any i in (0..pe.number_of_sections) : ((pe.sections[i].name==".RLPack"))
}
