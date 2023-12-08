import "pe"

rule EPWv12
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 06 57 1E 56 55 52 51 53 50 2E [4] 8C C0 05 [2] 2E [3] 8E D8 A1 [2] 2E }

	condition:
		$a0 at pe.entry_point
}
