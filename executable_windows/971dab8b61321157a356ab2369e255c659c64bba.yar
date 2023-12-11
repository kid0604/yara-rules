import "pe"

rule PluginToExev100BoBBobSoft
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern used by PluginToExe version 1.00 by BobSoft"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 29 C0 5D 81 ED D1 40 40 00 50 FF 95 B8 40 40 00 89 85 09 40 40 00 FF 95 B4 40 40 00 89 85 11 40 40 00 50 FF 95 C0 40 40 00 8A 08 80 F9 22 75 07 50 FF 95 C4 40 40 00 89 85 0D 40 40 00 8B 9D 09 40 40 00 60 6A 00 6A 01 53 81 C3 [3] 00 FF D3 61 6A 00 68 44 69 45 50 FF B5 0D 40 40 00 6A 00 81 C3 [3] 00 FF D3 83 C4 10 FF 95 B0 40 40 00 }

	condition:
		$a0 at pe.entry_point
}
