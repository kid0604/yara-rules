import "pe"

rule Frusionbiff
{
	meta:
		author = "malware-lu"
		description = "Detects Frusionbiff malware at the entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 EC 0C 53 55 56 57 68 04 01 00 00 C7 44 24 14 }

	condition:
		$a0 at pe.entry_point
}
