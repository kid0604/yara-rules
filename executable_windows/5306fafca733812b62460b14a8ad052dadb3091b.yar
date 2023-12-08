import "pe"

rule KBySV022shoooo
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 [4] E8 01 00 00 00 C3 C3 11 55 07 8B EC B8 [4] E8 }

	condition:
		$a0 at pe.entry_point
}
