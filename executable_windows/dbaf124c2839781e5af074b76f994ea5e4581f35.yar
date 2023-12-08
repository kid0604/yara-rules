import "pe"

rule ObsidiumV1304ObsidiumSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects Obsidium v1.3.0.4 software"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 02 [2] E8 ?? 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
