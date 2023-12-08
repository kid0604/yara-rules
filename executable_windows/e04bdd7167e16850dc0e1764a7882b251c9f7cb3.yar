import "pe"

rule AntiDote12BetaDemoSISTeam
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of AntiDote12BetaDemoSISTeam malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 69 D6 00 00 E8 C6 FD FF FF 68 69 D6 00 00 E8 BC FD FF FF 83 C4 08 E8 A4 FF FF FF 84 C0 74 2F 68 04 01 00 00 68 B0 21 60 00 6A 00 FF 15 08 10 60 00 E8 29 FF FF FF 50 68 88 10 60 00 68 78 10 60 00 68 B0 21 60 00 E8 A4 FD FF FF 83 C4 10 33 C0 C2 10 00 90 90 90 90 90 90 90 90 90 90 90 90 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 90 8B 44 24 04 53 55 56 8B 48 3C 57 03 C8 33 D2 8B 79 54 8B 71 38 8B C7 F7 F6 85 D2 74 0C 8B C7 33 D2 F7 F6 8B F8 47 0F AF FE 33 C0 33 DB 66 8B 41 14 8D 54 08 18 33 C0 }

	condition:
		$a0 at pe.entry_point
}
