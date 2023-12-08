import "pe"

rule Obsidium1341ObsidiumSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the Obsidium software based on specific byte patterns at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 01 ?? E8 2A 00 00 00 EB 04 [4] EB 02 [2] 8B 54 24 0C EB 03 [3] 83 82 B8 00 00 00 21 EB 02 [2] 33 C0 EB 03 [3] C3 EB 02 [2] EB 01 ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 [2] EB 03 [3] 50 EB 04 [4] 33 C0 EB 02 [2] 8B 00 EB 04 [4] C3 EB 02 [2] E9 FA 00 00 00 EB 02 [2] E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 03 [3] EB 04 [4] 64 67 8F 06 00 00 EB 04 [4] 83 C4 04 EB 02 [2] E8 C3 27 00 00 }

	condition:
		$a0 at pe.entry_point
}
