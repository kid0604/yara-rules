import "pe"

rule EXECryptor239compressedresources
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of compressed resources in files protected by EXECryptor version 2.39"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 51 68 [4] 59 81 F1 12 3C CB 98 E9 53 2C 00 00 F7 D7 E9 EB 60 00 00 83 45 F8 02 E9 E3 36 00 00 F6 45 F8 20 0F 84 1E 21 00 00 55 E9 80 62 00 00 87 0C 24 8B E9 [4] 00 00 23 C1 81 E9 [4] 57 E9 ED 00 00 00 0F 88 [4] E9 2C 0D 00 00 81 ED BB 43 CB 79 C1 E0 1C E9 9E 14 00 00 0B 15 [4] 81 E2 2A 70 7F 49 81 C2 9D 83 12 3B E8 0C 50 00 00 E9 A0 16 00 00 59 5B C3 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 E8 41 42 00 00 E9 93 33 00 00 31 DB 89 D8 59 5B C3 A1 [4] 8A 00 2C 99 E9 82 30 00 00 0F 8A [4] B8 01 00 00 00 31 D2 0F A2 25 FF 0F 00 00 E9 72 21 00 00 0F 86 57 0B 00 00 E9 [4] C1 C0 03 E8 F0 36 00 00 E9 41 0A 00 00 81 F7 B3 6E 85 EA 81 C7 [4] 87 3C 24 E9 74 52 00 00 0F 8E [4] E8 5E 37 00 00 68 B1 74 96 13 5A E9 A1 04 00 00 81 D1 49 C0 12 27 E9 50 4E 00 00 C1 C8 1B 1B C3 81 E1 96 36 E5 }

	condition:
		$a0 at pe.entry_point
}
