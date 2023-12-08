import "pe"

rule TangoBravo
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "2aa9cd3a2db2bd9dbe5ee36d9a5fc42b50beca806f9d644f387d5a680a580896"
		description = "Detects a specific target domain check in a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$targetDomainCheck = {5? 5? FF ?? 83 C4 08 85 C0 75 ?? 8? ?? 08 01 00 00 8? ?? 08 01 00 00 4? 8B ?? 84 ?? 75  }

	condition:
		$targetDomainCheck in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
