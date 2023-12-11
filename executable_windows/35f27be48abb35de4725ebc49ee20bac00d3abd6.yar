import "pe"

rule IndiaGolf
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "3dda69dfb254dcaea2ba6e8323d4b61ab1e130a0694f4c43d336cfb86a760c50"
		description = "Detects the presence of a specific code pattern used to generate random IDs"
		os = "windows"
		filetype = "executable"

	strings:
		$generateRandomID = {FF ?? 8B ?? C1 ?? 10 FF ?? 03 F8 89 [3] FF ?? 8B ?? C1 ?? 10 FF ?? 03 ?? 89}

	condition:
		$generateRandomID in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
