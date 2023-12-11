import "pe"

rule LimaAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "c9fbad7fc7ff7688776056be3a41714a1f91458a7b16c37c3c906d17daac2c8b"
		Status = "Signature is too loose to be useful."
		description = "Yara rule to detect LimaAlfa malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {33 C0 66 [2] 8B ?? 81 ?? 00 F0 FF FF 81 ?? 00 30 00 00 75 ?? 8B [3] 25 FF 0F 00 00 03 C7 01}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
