import "pe"

rule WhiskeyDelta
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group  trig@novetta.com"
		Source = "41badf10ef6f469dd1c3be201aba809f9c42f86ad77d7f83bc3895bfa289c635"
		description = "Detects WhiskeyDelta malware based on specific strings and decryption routine"
		os = "windows"
		filetype = "executable"

	strings:
		$decryption = {F3 A5 8B 7C 24 30 85 FF 7E ?? 8B 74 24 2C 8A 44 24 08 53 8A 4C 24 21 8A 5C 24 2B 32 C1 8A 0C 32 32 C3 32 C8 88 0C 32 B9 1E 00 00 00 8A 5C 0C 0C 	88 5C 0C 0D 49 	83 F9 FF 7F ?? 	42 }
		$s1 = "=====IsFile=====" wide
		$s2 = "=====4M=====" wide
		$s3 = "=====IsBackup=====" wide

	condition:
		2 of ($s*) or $decryption in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
