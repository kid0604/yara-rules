import "pe"

rule ObsidiumV1300ObsidiumSoftware
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting Obsidium v1.3.0.0 software"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 04 [4] E8 29 00 00 00 }
		$a1 = { EB 04 [4] E8 ?? 00 00 00 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
