import "pe"

rule DBPEv153
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 55 57 56 52 51 53 9C FA E8 [4] 5D 81 ED 5B 53 40 ?? B0 ?? E8 [4] 5E 83 C6 11 B9 27 [3] 30 06 46 49 75 FA }

	condition:
		$a0 at pe.entry_point
}
