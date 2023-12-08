import "pe"

rule RomeoBravo
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "95314a7af76ec36cfba1a02b67c2b81526a04e3b2f9b8fb9b383ffcbcc5a3d9b"
		description = "Detects a specific pattern in the .text section of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {E8 [4] 83 C4 10 85 C0 74 ?? B? 02 00 00 00 5? 83 C4 18 C3 6A 78 6A 01 8D [3] 6A 0C 5? 5? E8 [4] 83 C4 14 85 C0 74 ?? B8 02 00 00 00}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
