import "pe"

rule KiloAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		type = "Keylogger"
		SourceForDnscalcVariant1 = "b855d05ef7ab6582864c9b35052a1073a6eb7d0c7e9d97f524ec062715d71321"
		SourceForDnscalcVariant2 = "ddde628be8cd5db768b807510ae1319888e6c4550a5b9a0d54e17b9ec4aaa256"
		description = "Yara rule for detecting Keylogger type malware"
		os = "windows"
		filetype = "executable"

	strings:
		$keyxlate = {68 ?? 00 00 00 FF 15 [4] 66 ?? 01 80 75 ?? 6A ?? E8 [4] 83 C4 04 68 ?? 00 00 00 FF 15 [4] 66 ?? 01 80 75 ?? 6A ?? E8 [4] 83 C4 04 68 ?? 00 00 00 FF 15 [4] 66 ?? 01 80 75 ?? 6A ?? E8 [4] 83 C4 04 68 ?? 00 00 00 FF 15 [4] 66 ?? 01 80 75 ?? 6A ?? E8 [4] 83 C4 04}
		$keyxlateDnscalc1 = {	6A 2A C6 [6] D6 C6 [6] E1 C6 [6] BF C6 [6] C8 C6 [6] C3 C6 [6] BD	88 [6] FF 15 [4] 66 3D 01 80 75 ?? 	8D [6] 8D [6] 5? 6A 07 5? E8 [4] 50 E8 [4] 83 C4 10 }
		$keyxlateDnscalc2 = { 6A 2A C7 [5] D6 E1 BF C8 	66 [6] C3 BD 88 [5]	FF 15 [4] BA 01 80 FF FF 66 3B C2 75 ?? 8D [5] 5? 8D [5] 6A 07 5? E8 [4] 50 E8 [4] 83 C4 10 }

	condition:
		$keyxlate in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size)) or $keyxlateDnscalc1 in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size)) or $keyxlateDnscalc2 in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
