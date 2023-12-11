import "pe"

rule LimaDelta
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "81e6118a6d8bf8994ce93f940059217481bfd15f2757c48c589983a6af54cfcc"
		description = "Yara rule to detect specific file decoding and authentication buffer generation techniques"
		os = "windows"
		filetype = "executable"

	strings:
		$fileDecoder = {8B ?? ?? 83 ?? 10 81 ?? 6D 3A 71 58 89 ?? 33 ?? 66 ?? ?? F0 89 ?? 04 83 ?? 08 4? 75}
		$authenicateBufferGen = {BB 01 74 ?? FF 15 [4] 99 B? 32 00 00 00 F7 ?? 8B ?? 8D [3] 5? 5? E8 [4] 83 C4 08 83 ?? 46}

	condition:
		$authenicateBufferGen in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size)) or $fileDecoder in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
