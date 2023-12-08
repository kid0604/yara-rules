import "pe"

rule HotelAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "58dab205ecb1e0972027eb92f68cec6d208e5ab5.ex_"
		description = "Yara rule for detecting HotelAlfa malware"
		os = "windows"
		filetype = "executable"

	strings:
		$resourceHTML = "RSRC_HTML"
		$rscsDecoderLoop = {8A [2] 80 F1 ?? 88 [2] 8B [2] 40 3B ?? 72 EF}

	condition:
		$resourceHTML and $rscsDecoderLoop in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
