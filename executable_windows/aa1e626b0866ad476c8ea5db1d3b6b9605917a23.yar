import "pe"

rule Caracachs : sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"
		description = "Yara rule for detecting Caracachs sharedcode"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {B? 10 00 00 00 8B ?? C1 ?? 10 81 ?? FF 7F 00 00 03 ?? 8B ?? 8B ?? 83 ?? 0F 2B ?? D3 ?? 8B ?? D3 ?? 0B ?? 	89 ?? 	}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
