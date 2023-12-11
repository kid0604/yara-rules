import "pe"

rule RC4SboxKeyGen : sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "RT_RCDATA_101.bin.bin"
		description = "Detects the generation of RC4 S-box key in shared code"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {	8A [3] 	8B ?? 	81 ?? 0F 00 00 80 79 ?? 4? 83 ?? F0 4? 	}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
