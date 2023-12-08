import "pe"

rule RomeoJuliettMikeTwo
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "819722ba1c5b9d0b360c54cbdd3811d0cac1a9230720b3ed4815f78bcacb3653_d1ba9ba2987f59d99ce4bf09393c0521c4d1f2961c5aeed4e0bf86e78303d27c"
		description = "Yara rule for detecting specific strings and patterns in a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$recvFunc = { 81 [3] 33 27 00 00 75 ?? 8D [3] 5? FF 15 [4] 8B [3] 83 ?? 04 8B ?? 4? 83 ?? 64 }
		$apiLoader = { E8 [4] 8B [3] 8B ?? 5? E8 [4] 83 C4 08 85 ?? 74 ?? 85 C0 74 ?? 5? FF 15 [4] 5? 8B ?? E8 [4] 83 C4 04 5? 5? FF 15 }
		$recvPeers = { 68 B8 0B 00 00 FF 15 [4] 6A 01 [0-4] 68 B0 04 00 00 51 8B ?? [1-4] B0 04 00 00 E8 [4] 83 F8 FF	}
		$logFileName = "KBD_%%s_%%02d%%02d%%02d%%02d%%02d.CAT"

	condition:
		$recvFunc in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size)) or $apiLoader in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size)) or $recvPeers in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size)) or $logFileName
}
