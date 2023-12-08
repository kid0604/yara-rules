import "pe"

rule Obsidium1333ObsidiumSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the Obsidium software based on specific byte patterns at the entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 02 [2] E8 29 00 00 00 EB 03 [3] EB 03 [3] 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 28 EB 03 [3] 33 C0 EB 01 ?? C3 EB 04 [4] EB 02 [2] 64 67 FF 36 00 00 EB 04 [4] 64 67 89 26 00 00 EB 02 [2] EB 04 [4] 50 EB 04 }
		$a1 = { EB 02 [2] E8 29 00 00 00 EB 03 [3] EB 03 [3] 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 28 EB 03 [3] 33 C0 EB 01 ?? C3 EB 04 [4] EB 02 [2] 64 67 FF 36 00 00 EB 04 [4] 64 67 89 26 00 00 EB 02 [2] EB 04 [4] 50 EB 04 [4] 33 C0 EB 01 ?? 8B 00 EB 03 [3] C3 EB 03 [3] E9 FA 00 00 00 EB 03 [3] E8 D5 FF FF FF EB 04 [4] EB 04 [4] 58 EB 01 ?? EB 03 [3] 64 67 8F 06 00 00 EB 04 [4] 83 C4 04 EB 04 [4] E8 2B 27 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
