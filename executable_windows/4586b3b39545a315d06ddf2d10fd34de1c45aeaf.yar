import "pe"

rule UnoPiX103110BaGiE
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 EC 04 C7 04 24 00 [3] C3 00 [2] 00 00 00 00 00 00 00 00 00 00 00 00 [2] 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 [2] 00 00 10 00 00 00 00 00 00 02 00 00 ?? 00 00 ?? 00 00 [2] 00 00 00 10 00 00 10 00 00 00 00 00 00 10 }

	condition:
		$a0 at pe.entry_point
}
