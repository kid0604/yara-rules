import "pe"

rule ObsidiumV130XObsidiumSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects Obsidium v1.3.0.x by Obsidium Software"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 03 [3] E8 2E 00 00 00 EB 04 [4] EB 04 [4] 8B [3] EB 04 [4] 83 [6] EB 01 ?? 33 C0 EB 04 [4] C3 }

	condition:
		$a0 at pe.entry_point
}
