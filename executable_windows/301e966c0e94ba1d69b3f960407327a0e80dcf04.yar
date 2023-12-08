import "pe"

rule Obsidium1331ObsidiumSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Obsidium software in Windows executables"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 01 ?? E8 29 00 00 00 EB 02 [2] EB 03 [3] 8B 54 24 0C EB 02 [2] 83 82 B8 00 00 00 24 EB 04 [4] 33 C0 EB 02 [2] C3 EB 02 [2] EB 02 [2] 64 67 FF 36 00 00 EB 04 [4] 64 67 89 26 00 00 EB 01 ?? EB 02 [2] 50 EB 01 ?? 33 C0 EB 04 [4] 8B 00 EB 03 [3] C3 EB 03 [3] E9 FA 00 00 00 EB 02 [2] E8 D5 FF FF FF EB 01 ?? EB 04 [4] 58 EB 02 [2] EB 04 [4] 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 02 [2] E8 5F 27 00 00 }

	condition:
		$a0 at pe.entry_point
}
