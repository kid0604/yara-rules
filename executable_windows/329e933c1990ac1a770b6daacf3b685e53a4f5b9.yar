import "pe"

rule Reg2Exe225byJanVorel
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of PE files, which may indicate a malicious executable"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 68 00 00 00 68 00 00 00 00 68 70 7D 40 00 E8 AE 20 00 00 83 C4 0C 68 00 00 00 00 E8 AF 52 00 00 A3 74 7D 40 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 9C 52 00 00 A3 70 7D 40 00 E8 24 50 00 00 E8 E2 48 00 00 E8 44 34 00 00 E8 54 28 00 00 E8 98 27 00 00 E8 93 20 00 00 68 01 00 00 00 68 D0 7D 40 00 68 00 00 00 00 8B 15 D0 7D 40 00 E8 89 8F 00 00 B8 00 00 10 00 68 01 00 00 00 E8 9A 8F 00 00 FF 35 A4 7F 40 00 68 00 01 00 00 E8 3A 23 00 00 8D 0D A8 7D 40 00 5A E8 5E 1F 00 00 FF 35 A8 7D 40 00 68 00 01 00 00 E8 2A 52 00 00 A3 B4 7D 40 00 FF 35 A4 7F 40 00 FF 35 B4 7D 40 00 FF 35 A8 7D 40 00 E8 5C 0C 00 00 8D 0D A0 7D 40 00 5A E8 26 1F 00 00 FF 35 }

	condition:
		$a0 at pe.entry_point
}
