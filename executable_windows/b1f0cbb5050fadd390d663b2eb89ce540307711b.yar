import "pe"

rule INDICATOR_EXE_Packed_Titan
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Titan"
		snort2_sid = "930010-930012"
		snort3_sid = "930003"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = { 00 00 ?? 2e 74 69 74 61 6e 00 00 }

	condition:
		uint16(0)==0x5a4d and all of them or for any i in (0..pe.number_of_sections) : ((pe.sections[i].name==".titan"))
}
