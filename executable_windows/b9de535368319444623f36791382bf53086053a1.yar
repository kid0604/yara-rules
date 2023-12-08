import "pe"

rule Minke101byCodius
{
	meta:
		author = "malware-lu"
		description = "Detects Minke101 malware by Codius"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 [5] 10 E8 7A F6 FF FF BE 68 66 00 10 33 C0 55 68 DB 40 00 10 64 FF 30 64 89 20 E8 FA F8 FF FF BA EC 40 00 10 8B C6 E8 F2 FA FF FF 8B D8 B8 6C 66 00 10 8B 16 E8 88 F2 FF FF B8 6C 66 00 10 E8 76 F2 FF FF 8B D0 8B C3 8B 0E E8 E3 E4 FF FF E8 2A F9 FF FF E8 C1 F8 FF FF B8 6C 66 00 10 8B 16 E8 6D FA FF FF E8 14 F9 FF FF E8 AB F8 FF FF 8B 06 E8 B8 E3 FF FF 8B D8 B8 6C 66 00 10 E8 38 F2 FF FF 8B D3 8B 0E E8 A7 E4 FF [4] C4 FB FF FF E8 E7 F8 FF FF 8B C3 E8 B0 E3 FF FF E8 DB F8 FF FF 33 C0 5A 59 59 64 89 10 68 E2 40 00 10 C3 E9 50 EB FF FF EB F8 5E 5B E8 BB EF FF FF 00 00 00 43 41 31 38 }

	condition:
		$a0 at pe.entry_point
}
