import "pe"

rule GenerateTLSClientHelloPacket_Test : sharedcode
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "eff542ac8e37db48821cb4e5a7d95c044fff27557763de3a891b40ebeb52cc55.ex_"
		description = "Detects the presence of TLS Client Hello packet generation in a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {25 07 00 00 80 79 ?? 4? 	83 ?? F8 4? }

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
