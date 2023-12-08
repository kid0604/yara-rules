import "pe"

rule RandomTimestampGenerator : sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "RT_RCDATA_101.bin.bin joanap baseline sample"
		description = "Detects Random Timestamp Generator in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {	66 81 [3] FE FF FF [1-4] 99 B9 0C 00 00 00 F7 [1-4] 42 	66 89 [3]  FF D6 99 B9 1C 00 00 00 F7 [1-4] 42 	66 89 [3] FF D6 99 B9 17 00 00 00 F7 [1-4] 42 66 89 [3] FF D6 99 B9 3B 00 00 00 F7 [1-4] 42 66 89 [3] FF D6 99 	B9 3B 00 00 00 	F7 }

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
