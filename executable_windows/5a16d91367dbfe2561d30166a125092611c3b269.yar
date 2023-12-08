import "pe"

rule ObsidiumV1258V133XObsidiumSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects Obsidium software version 1.25.8 and 1.33.x"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 01 ?? E8 ?? 00 00 00 EB 02 [2] EB }

	condition:
		$a0 at pe.entry_point
}
