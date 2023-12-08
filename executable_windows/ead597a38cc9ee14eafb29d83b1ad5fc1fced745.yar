import "pe"

rule LimaBravo
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "Mwsagent.dll"
		description = "Detects the presence of a specific string in the Mwsagent.dll file"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {83 ?? 34 83 ?? 0A [0-2] 7E ?? 5? C6 ?? 4D C6 [2] 5A E8}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
