import "pe"

rule Obsidium1334ObsidiumSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the Obsidium1334ObsidiumSoftware malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 02 [2] E8 29 00 00 00 EB 03 [3] EB 02 [2] 8B 54 24 0C EB 03 [3] 83 82 B8 00 00 00 25 EB 02 [2] 33 C0 EB 02 [2] C3 EB 03 [3] EB 01 ?? 64 67 FF 36 00 00 EB 02 [2] 64 67 89 26 00 00 EB 02 [2] EB 04 [4] 50 EB 02 [2] 33 }
		$a1 = { EB 02 [2] E8 29 00 00 00 EB 03 [3] EB 02 [2] 8B 54 24 0C EB 03 [3] 83 82 B8 00 00 00 25 EB 02 [2] 33 C0 EB 02 [2] C3 EB 03 [3] EB 01 ?? 64 67 FF 36 00 00 EB 02 [2] 64 67 89 26 00 00 EB 02 [2] EB 04 [4] 50 EB 02 [2] 33 C0 EB 01 ?? 8B 00 EB 04 [4] C3 EB 03 [3] E9 FA 00 00 00 EB 02 [2] E8 D5 FF FF FF EB 02 [2] EB 03 [3] 58 EB 02 [2] EB 03 [3] 64 67 8F 06 00 00 EB 03 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
