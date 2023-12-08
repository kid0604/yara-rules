import "pe"

rule NTPacker10ErazerZ
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of NTPacker10ErazerZ malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 C4 E0 53 33 C0 89 45 E0 89 45 E4 89 45 E8 89 45 EC B8 [2] 40 00 E8 [2] FF FF 33 C0 55 68 [2] 40 00 64 FF 30 64 89 20 8D 4D EC BA [2] 40 00 A1 [2] 40 00 E8 ?? FC FF FF 8B 55 EC B8 [2] 40 00 E8 [2] FF FF 8D 4D E8 BA [2] 40 00 A1 [2] 40 00 E8 ?? FE FF FF 8B 55 E8 B8 [2] 40 00 E8 [2] FF FF B8 [2] 40 00 E8 ?? FB FF FF 8B D8 A1 [2] 40 00 BA [2] 40 00 E8 [2] FF FF 75 26 8B D3 A1 [2] 40 00 E8 [2] FF FF 84 C0 75 2A 8D 55 E4 33 C0 E8 [2] FF FF 8B 45 E4 8B D3 E8 [2] FF FF EB 14 8D 55 E0 33 C0 E8 [2] FF FF 8B 45 E0 8B D3 E8 [2] FF FF 6A 00 E8 [2] FF FF 33 C0 5A 59 59 64 89 10 68 [2] 40 00 8D 45 E0 BA 04 00 00 00 E8 [2] FF FF C3 E9 [2] FF FF EB EB 5B E8 [2] FF FF 00 00 00 FF FF FF FF 01 00 00 00 25 00 00 00 FF FF FF FF 01 00 00 00 5C 00 00 00 FF FF FF FF 06 00 00 00 53 45 52 56 45 52 00 00 FF FF FF FF 01 00 00 00 31 }

	condition:
		$a0 at pe.entry_point
}
