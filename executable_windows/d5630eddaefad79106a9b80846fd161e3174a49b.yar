import "pe"

rule CPUInfoExtraction
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "Cmd10010_296fcc9d611ca1b8f8288192d6d854cf4072853010cc65cb0c7f958626999fbd.bin"
		description = "Detects CPU information extraction technique"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {68 00 00 00 80 8B ?? 8B ?? 04 89 [3] 8B ?? 08 89 [3] 8B ?? 0C 8D [3] 89 [5] 5? 8B ?? 89 [5] E8 [4] 8B ?? 8B ?? 	3D 00 00 00 80 8B ?? 04 }

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
