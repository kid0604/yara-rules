import "pe"

rule SierraBravo_One
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		description = "Detects a specific spreader setup in a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$spreaderSetup = {68 7E 66 04 80 5? E8 [4] 6A 32 89 B4 [5] C7 84 [5] 01 00 00 00 C7 44 [2] 03 00 00 00 C7 44 [2] 00 00 00 00 }

	condition:
		$spreaderSetup in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
