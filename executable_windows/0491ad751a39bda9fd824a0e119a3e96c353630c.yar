import "pe"

rule IndiaWhiskey
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "0c729deec341267c5a9a2271f20266ac3b0775d70436c7770ddc20605088f3b4"
		Description = "Winsec Installer"
		description = "Yara rule for detecting Winsec Installer"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {FF 15 [4] 83 C4 18 8D [5] 5? 5? 5? 5? 5? 5? 6A 01	[0-2] 6A 02 68 20 01 00 00 68 FF 01 0F 00 FF 75 ?? FF 75 ?? (5? | FF 75 ??) FF 15}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
