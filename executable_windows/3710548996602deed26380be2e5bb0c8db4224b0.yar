import "pe"

rule ObsidiumV1258ObsidiumSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Obsidium v1.2.5.8 software"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 01 ?? E8 ?? 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
