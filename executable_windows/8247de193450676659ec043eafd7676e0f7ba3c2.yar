import "pe"

rule DBPEv210_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 6A 10 73 0B EB 02 C1 51 E8 06 [3] C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 01 E8 79 E0 7A 01 75 83 C4 04 9D EB 01 75 68 5F 20 40 ?? E8 B0 EF FF FF 72 03 73 01 75 BE }

	condition:
		$a0 at pe.entry_point
}
