import "pe"

rule Obsidium13017Obsidiumsoftware
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting Obsidium software"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 02 [2] E8 28 00 00 00 EB 04 [4] EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 02 [2] 33 C0 EB 03 [3] C3 EB 03 [3] EB 02 [2] 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 [3] EB 04 [4] 50 EB 04 }

	condition:
		$a0 at pe.entry_point
}
