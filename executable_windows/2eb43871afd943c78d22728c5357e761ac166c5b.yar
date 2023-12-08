import "pe"

rule Obsidium1200ObsidiumSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Obsidium software by looking for a specific byte sequence at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 02 [2] E8 3F 1E 00 00 }

	condition:
		$a0 at pe.entry_point
}
