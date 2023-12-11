import "pe"

rule RomeoFoxtrot
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		Source = "dropped.bin"
		Source_relativeCalls = "635bebe95671336865f8a546f06bf67ab836ea35795581d8a473ef2cd5ff4a7f"
		description = "Detects a specific network communication pattern and a response string in a dropped binary file"
		os = "windows"
		filetype = "executable"

	strings:
		$connect = { C7 [3] 01 00 00 00 8B [6] C7 [3] 00 00 20 03 5? 89 [3] ( FF 15 | E8 ) [4] 6A 06 6A 01 6A 02 66 [4] 66 [4] 02 00 ( FF 15 | E8 ) [4] 83 F8 FF 89 [2] 0F 84 [4] [0-7] 8D [3] 6A 04 5? 68 02 10 00 00 68 FF FF 00 00 5? ( FF D? | E8 [3] ??) 8B [2] 8D [3] 6A 04 5? 68 01 10 00 00 68 FF FF 00 00 5? ( FF D? | E8 [3] ??) }
		$response = "RESPONSE 200 OK!!!"

	condition:
		$response or $connect in ((pe.sections[pe.section_index(".text")].raw_data_offset)..(pe.sections[pe.section_index(".text")].raw_data_offset+pe.sections[pe.section_index(".text")].raw_data_size))
}
