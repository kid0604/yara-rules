import "pe"

rule RomeoGolf
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "7322d6b9328a9c708518c99b03a4ed3aa6ba943d7b439f6b1925e6d52a1828fe"
		description = "Detects the presence of a specific code pattern used for generating unique identifiers"
		os = "windows"
		filetype = "executable"

	strings:
		$idGen = {FF 15 [4] 50 E8 [4] 83 C4 04 E8 [4] C1 ?? 10 89 [2] E8 [4] 01 [2] E8 [4] C1 ?? 10 89 [2] E8 [4] ?? ?? ?? }

	condition:
		$idGen in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
