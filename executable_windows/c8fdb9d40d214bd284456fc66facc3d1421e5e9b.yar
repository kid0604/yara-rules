import "pe"

rule SierraJuliettMikeOne
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		description = "Detects a specific communication key and handshake pattern in a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$commKey = { 10 20 30 40 50 60 70 80 90 11 12 13 1A FF EE 48 }
		$handshake = { 68 30 75 00 00 [4] 6A 04 5? 5? C? [3] 00 10 00 00 E8 [7] 83 F8 FF 0F 84 ?? ?? 00 00 8? [3] 5? E8 [4] 6A 00 68 30 75 00 00 }

	condition:
		$commKey in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset+pe.sections[pe.section_index(".data")].raw_data_size)) and $handshake in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
