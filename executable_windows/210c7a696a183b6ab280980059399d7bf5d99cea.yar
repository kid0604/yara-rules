import "pe"

rule Obsidium1336ObsidiumSoftware
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting files protected by Obsidium software"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 04 [4] E8 28 00 00 00 EB 01 [7] 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 26 EB 04 [4] 33 C0 EB 01 ?? C3 EB 03 [3] EB 04 [4] 64 67 FF 36 00 00 EB 04 [4] 64 67 89 26 00 00 EB 03 [3] EB 04 [4] 50 EB 01 ?? 33 C0 EB 02 [2] 8B 00 EB 04 [4] C3 EB 04 [4] E9 FA 00 00 00 EB 03 [3] E8 D5 FF FF FF EB 01 ?? EB 03 [3] 58 EB 02 [2] EB 04 [4] 64 67 8F 06 00 00 EB 04 }

	condition:
		$a0
}
