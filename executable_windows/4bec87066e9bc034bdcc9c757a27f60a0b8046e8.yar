import "pe"

rule IndiaEcho
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "66a21f8c72bb4f314604526e9bf1736f75b06cf37dd3077eb292941b476c3235"
		description = "Detects the IndiaEcho malware based on specific byte patterns"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {69 ?? 28 01 00 00 5? 5? FF B5 [4] E8 [4] 8B [5] 69 ?? 28 01 00 00	50 8B [5] (05 08 01 00 00 | 03 ??) 50 FF [5] E8 [4] 83 C4 ?? 8B [5] 69 ?? 28 01 00 00 (81 C7 08 01 00 00 | 03 ??)}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
