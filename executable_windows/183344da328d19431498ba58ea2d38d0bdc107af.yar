import "pe"

rule INDICATOR_EXE_Packed_Themida
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Themida"
		snort2_sid = "930067-930069"
		snort3_sid = "930024"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = ".themida" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them or for any i in (0..pe.number_of_sections) : ((pe.sections[i].name==".themida"))
}
