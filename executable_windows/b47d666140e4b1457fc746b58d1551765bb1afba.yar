import "pe"

rule Obsidium1300ObsidiumSoftware
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting the Obsidium1300 Obsidium Software"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 04 [4] E8 29 00 00 00 EB 02 [2] EB 01 ?? 8B 54 24 0C EB 02 [2] 83 82 B8 00 00 00 22 EB 02 [2] 33 C0 EB 04 [4] C3 EB 04 [4] EB 04 [4] 64 67 FF 36 00 00 EB 04 [4] 64 67 89 26 00 00 EB 04 [4] EB 01 ?? 50 EB 03 [3] 33 C0 EB 02 [2] 8B 00 EB 01 ?? C3 EB 04 [4] E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 02 [2] EB 03 [3] 58 EB 04 [4] EB 01 ?? 64 67 8F 06 00 00 EB 02 [2] 83 C4 04 EB 02 [2] E8 47 26 00 00 }

	condition:
		$a0 at pe.entry_point
}
