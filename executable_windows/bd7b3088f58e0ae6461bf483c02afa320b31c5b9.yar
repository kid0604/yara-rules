import "pe"

rule WhiskeyCharlie
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "47ff4f73738acc2f8433dccb2caf980d7444d723ccf2968d69f88f8f96405f96"
		description = "Detects WhiskeyCharlie malware based on specific byte patterns in the .text section"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {66 89 55 DC E8 [4] 6A 0C 	99 59 F7 F9 42 66 89 55 DE E8 [4] 6A 1C 99 59 F7 F9 42 66 89 55 E2 E8 [4] 6A 18 99 59 F7 F9 66 89 55 E4 E8 [4] 6A 3C 99 59 F7 F9 66 89 55 E6 E8 [4] 6A 3C 99 59 F7 F9 }

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
