import "pe"

rule XORDecodeA7 : sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"
		description = "Detects XOR decoding in a specific Windows executable"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {	8A [2] 	8B ??	34 A7 	46 88 ?? 83 ?? FF 33 ?? 4? F2 AE F7 ?? 	4? 3B ?? }

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
