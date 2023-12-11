import "pe"

rule IndiaBravo_RomeoCharlie
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "58ad28ac4fb911abb6a20382456c4ad6fe5c8ee5.ex_"
		Status = "Signature is too loose to be useful."
		description = "Detects the IndiaBravo_RomeoCharlie malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {50 68 7E 66 04 80 8B 8D [4] 51 FF 15 [4] 83 F8 FF 75}
		$b1 = "xc123465-efff-87cc-37abcdef9"
		$b2 = "[Check] - PORT ERROR..." wide
		$b3 = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d"

	condition:
		2 of ($b*) or $a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
