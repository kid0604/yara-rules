import "pe"

rule SierraBravo_Two
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		description = "Detects SierraBravo_Two malware based on specific strings and conditions"
		os = "windows"
		filetype = "executable"

	strings:
		$smbComNegotiationPacketGen = { 66 C7 ?? 0E 07 C8 [0-32] C7 ?? 39 D4 00 00 80 [0-32] 66 C7 ?? 25 FF 00 [0-32] 66 C7 ?? 27 A4 00 [0-32]	66 C7 ?? 29 04 41 [0-32] 66 C7 ?? 2B 32 00}
		$lib = "!emCFgv7Xc8ItaVGN0bMf"
		$api1 = "!ctRHFEX5m9JnZdDfpK"
		$api2 = "!emCFgv7Xc8ItaVGN0bMf"
		$api3 = "!VWBeBxYx1nzrCkBLGQO"
		$pwd = "iamsorry!@1234567"

	condition:
		$smbComNegotiationPacketGen in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size)) or ($pwd in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset+pe.sections[pe.section_index(".data")].raw_data_size)) and ($lib in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset+pe.sections[pe.section_index(".data")].raw_data_size)) or $api1 in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset+pe.sections[pe.section_index(".data")].raw_data_size)) or $api2 in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset+pe.sections[pe.section_index(".data")].raw_data_size)) or $api3 in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset+pe.sections[pe.section_index(".data")].raw_data_size))))
}
