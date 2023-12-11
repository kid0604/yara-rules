import "pe"

rule XJXPALLiNSoN
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [2] 40 00 68 [2] 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 44 53 56 57 66 9C }

	condition:
		$a0 at pe.entry_point
}
