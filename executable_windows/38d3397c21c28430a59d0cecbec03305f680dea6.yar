import "pe"

rule StringDotSimplified : sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"
		description = "Detects a specific string pattern in the .text section of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {	F3 AB 	80 ?? 00 	74 ?? 	8A 02 	3C 2E 	74 ?? 	3C 20 	74 ?? 	88 06 	46 }

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
