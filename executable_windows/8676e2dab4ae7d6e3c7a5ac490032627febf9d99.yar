import "pe"

rule Obsidiumv1300ObsidiumSoftware
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting the Obsidiumv1300ObsidiumSoftware malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 04 25 80 34 CA E8 29 00 00 00 EB 02 C1 81 EB 01 3A 8B 54 24 0C EB 02 32 92 83 82 B8 00 00 00 22 EB 02 F2 7F 33 C0 EB 04 65 7E 14 79 C3 EB 04 05 AD 7F 45 EB 04 05 65 0B E8 64 67 FF 36 00 00 EB 04 0D F6 A8 7F 64 67 89 26 00 00 EB 04 8D 68 C7 FB EB 01 6B }
		$a1 = { EB 04 25 80 34 CA E8 29 00 00 00 EB 02 C1 81 EB 01 3A 8B 54 24 0C EB 02 32 92 83 82 B8 00 00 00 22 EB 02 F2 7F 33 C0 EB 04 65 7E 14 79 C3 EB 04 05 AD 7F 45 EB 04 05 65 0B E8 64 67 FF 36 00 00 EB 04 0D F6 A8 7F 64 67 89 26 00 00 EB 04 8D 68 C7 FB EB 01 6B 50 EB 03 8A 0B 93 33 C0 EB 02 28 B9 8B 00 EB 01 04 C3 EB 04 65 B3 54 0A E9 FA 00 00 00 EB 01 A2 E8 D5 FF FF FF EB 02 2B 49 EB 03 7C 3E 76 58 EB 04 B8 94 92 56 EB 01 72 64 67 8F 06 00 00 EB 02 23 72 83 C4 04 EB 02 A9 CB E8 47 26 00 00 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
