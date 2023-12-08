import "pe"

rule RomeoWhiskey_One
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "5d21e865d57e9798ac7c14a6ad09c4034d103f3ea993295dcdf8a208ea825ad7"
		description = "Detects the presence of a specific pattern in the .text section of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a = {	FF 15 [4]  0F B7 C0 8B C8 [2-4] C1 E9 ?? 81 F1 [2] 00 00 [0-2] 	C1 E0 10 0B C8 	}

	condition:
		$a in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
