import "pe"

rule DynamicAPILoading : sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"
		description = "Detects dynamic API loading in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {	83 C4 ?? 5? 5? 	FF 15 [4] 68 [4] A3 [4]	E8 [4]	83 C4 ?? 5? 5? 	FF 15 [4] 68 [4] A3 [4]	E8 [4] 83 C4 ?? 5?  5? 	FF 15 [4] 68 [4] A3 [4]	E8}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
