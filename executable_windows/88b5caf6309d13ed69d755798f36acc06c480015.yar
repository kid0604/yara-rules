import "pe"

rule FSGv10
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE [4] 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }

	condition:
		$a0 at pe.entry_point
}
