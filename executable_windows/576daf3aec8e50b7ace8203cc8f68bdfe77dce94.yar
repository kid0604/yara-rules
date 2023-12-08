import "pe"

rule IndiaJuliett_1
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source_writeFile = "a164c0ba0be7c33778c12a6457e9c55a2935564a"
		description = "Detects suspicious activities related to file writing and data manipulation"
		os = "windows"
		filetype = "executable"

	strings:
		$configFilename = {00 73 63 61 72 64 70 72 76  2E 64 6C 6C 00}
		$suicideScript = ":R\nIF NOT EXIST %s GOTO E\ndel /a %s\nGOTO R\n:E\ndel /a d.bat"
		$commKey = { 10 20 30 40 50 60 70 80 90 11 12 13 1A FF EE 48 }
		$handshake = { 68 30 75 00 00 [4] 6A 04 5? 5? C? [3] 00 10 00 00 E8 [7] 83 F8 FF 0F 84 ?? ?? 00 00 8? [3] 5? E8 [4] 6A 00 68 30 75 00 00 }
		$writeFile = {68 00 28 00 00 5?	E8 [4-7] 8D [3] 6A 00 5? 68 00 28 00 00 5? 5? FF 15 [4] 81 ?? 00 28 00 00 81 ?? 00 28 00 00 81 ?? 00 28 00 00}

	condition:
		($configFilename in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset+pe.sections[pe.section_index(".data")].raw_data_size)) or $suicideScript in ((pe.sections[pe.section_index(".data")].raw_data_offset)..(pe.sections[pe.section_index(".data")].raw_data_offset+pe.sections[pe.section_index(".data")].raw_data_size))) or ($handshake in ((pe.sections[pe.section_index(".rsrc")].raw_data_offset)..(pe.sections[pe.section_index(".rsrc")].raw_data_offset+pe.sections[pe.section_index(".rsrc")].raw_data_size)) and $commKey in ((pe.sections[pe.section_index(".rsrc")].raw_data_offset)..(pe.sections[pe.section_index(".rsrc")].raw_data_offset+pe.sections[pe.section_index(".rsrc")].raw_data_size))) or $writeFile in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
