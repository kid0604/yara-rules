import "pe"

rule IndiaBravo_RomeoBravo
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "6e3db4da27f12eaba005217eba7cd9133bc258c97fe44605d12e20a556775009"
		description = "Detects the presence of IndiaBravo_RomeoBravo malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {E8 [4] 68 [2] 00 00 68 [4] A3 [4]	89 15 [4] E8 [4] 83 C4 08 8D [3] 6A 00 5? 68 [2] 00 00 	68 [4] 5? FF 15 [4] 5? 	FF 15}
		$b1 = "tmscompg.msi" wide
		$b2 = "cvrit000.bat"

	condition:
		2 of ($b*) or $a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
