import "pe"

rule DNSCalcStyleEncodeAndDecode : sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "975522bc3e07f7aa2c4a5457e6cc16c49a148b9f731134b8971983225835577e"
		description = "Detects DNSCalcStyle encoding and decoding in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {8A ?? 80 ?? ?? 80 ?? ?? 88 ?? 4? 4? 75 ?? }

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
