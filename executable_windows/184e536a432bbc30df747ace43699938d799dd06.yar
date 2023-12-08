import "pe"

rule nPack111502006BetaNEOx
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 3D [5] 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 [4] 2B 05 [4] A3 [4] E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 A1 [4] C7 05 [8] 01 05 [4] FF 35 [4] C3 C3 56 57 68 [4] FF 15 [4] 8B 35 [4] 8B F8 68 [4] 57 FF D6 68 [4] 57 A3 [4] FF D6 5F A3 [4] 5E C3 }

	condition:
		$a0 at pe.entry_point
}
