import "pe"

rule INDICATOR_EXE_Packed_MEW
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with MEW"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_sections) : ((pe.sections[i].name=="MEW" or pe.sections[i].name=="\x02\xd2u\xdb\x8a\x16\xeb\xd4"))
}
