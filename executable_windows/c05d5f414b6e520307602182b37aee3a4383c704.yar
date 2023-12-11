import "pe"

rule RomeoCharlie
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "a82108ef7115931b3fbe1fab99448c4139e22feda27c1b1d29325710671154e8"
		description = "Detects potential indicators of compromise related to authentication, startup relay threads, and cryptographic operations"
		os = "windows"
		filetype = "executable"

	strings:
		$auth1 = "Success - Accept Auth"
		$auth2 = "Fail - Accept Auth"
		$startupRelayThreads = {81 ?? FF FF 00 00 8B ?? 5? C1 ?? 10 81 ?? FF FF 00 00 8B ?? 8B ?? 81 ?? FF FF 00 00 C1 ?? 10 6A 00 0B ?? 6A 00 	50 68 [4] 6A 00 6A 00 FF 15 [4] C1 ?? 10 }
		$crypto = {2? 00 20 00 00 3? 00 20 00 00 0F [2] 81 ?? 80 00 00 00 33 ?? 80 ?? 80 0F [2] 03 ?? 33 ?? 83 ?? 01 }

	condition:
		all of ($auth*) or $startupRelayThreads in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size)) or $crypto in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
