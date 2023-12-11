import "pe"

rule RomeoWhiskey_Two
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "a8d88714f0bc643e76163d1b8972565e78a159292d45a8218d0ad0754c8f561d"
		description = "Detects a specific pattern in the .text section of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {FF 15 [4] 66 8B C8 [3-4] 	66 81 F1 40 1C 	66 D1 E9 81 C1 E0 56 00 00 0F B7 C9 0F B7 C0 81 F1 30 32 00 00 	C1 E0 10 0B C8 }

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
