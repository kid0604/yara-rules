import "pe"

rule INDICATOR_EXE_Packed_MPress
{
	meta:
		author = "ditekSHen"
		description = "Detects executables built or packed with MPress PE compressor"
		snort2_sid = "930031-930033"
		snort3_sid = "930011"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = ".MPRESS1" fullword ascii
		$s2 = ".MPRESS2" fullword ascii

	condition:
		uint16(0)==0x5a4d and 1 of them or for any i in (0..pe.number_of_sections) : ((pe.sections[i].name==".MPRESS1" or pe.sections[i].name==".MPRESS2"))
}
