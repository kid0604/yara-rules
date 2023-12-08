import "pe"

rule FSGv131_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects a specific code pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE [4] 53 BB [4] B2 80 A4 B6 80 FF D3 73 F9 33 C9 }

	condition:
		$a0 at pe.entry_point
}
