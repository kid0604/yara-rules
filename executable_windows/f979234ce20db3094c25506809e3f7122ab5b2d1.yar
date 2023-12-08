import "pe"

rule Obsidium13037ObsidiumSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the Obsidium software in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 02 [2] E8 26 00 00 00 EB 03 [3] EB 01 ?? 8B 54 24 0C EB 04 [4] 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 [2] C3 EB 01 ?? EB 04 [4] 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 [3] 50 EB 03 [3] 33 C0 EB 03 [3] 8B 00 EB 04 [4] C3 EB 03 [3] E9 FA 00 00 00 EB 03 [3] E8 D5 FF FF FF EB 04 [4] EB 01 ?? 58 EB 02 [2] EB 03 [3] 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 [3] E8 23 27 00 00 }

	condition:
		$a0 at pe.entry_point
}
