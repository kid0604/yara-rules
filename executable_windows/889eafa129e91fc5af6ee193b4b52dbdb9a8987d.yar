import "pe"

rule SierraAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "4d4b17ddbcf4ce397f76cf0a2e230c9d513b23065f746a5ee2de74f447be39b9.ex_"
		description = "Detects suspicious strings and patterns in a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$connectTest = {8D [3] 5? 68 7E 66 04 80 5? E8 [4] 8D [3] 6A 10 5? 5? E8 [4] 8B [6] 8D [3] 5? 8D [3] 6A 00 5? 6A 00 6A 00 89 [3] 89 [3] 89 [3] C7 [7] E8 [4] 33 ?? 5? 85 C0 0F 9F ?? 8B ?? E8}
		$maths = { E8 [4] 8B ?? E8 [4] 0F AF ?? E8 [4] 0F AF ?? 99 33 ?? 2B ?? 33 ?? F7 ?? 8B ?? 5? E8}
		$s1 = "recdiscm32.exe"
		$s2 = "\\\\%s\\shared$\\syswow64"
		$s3 = "\\\\%s\\shared$\\system32"

	condition:
		$connectTest in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size)) or $maths in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size)) or 3 of ($s*)
}
