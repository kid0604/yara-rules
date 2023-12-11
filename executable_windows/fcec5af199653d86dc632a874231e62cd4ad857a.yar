import "pe"

rule Mew501NorthFoxHCC
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 ?? 04 ?? C0 C8 ?? AA E2 F4 C3 00 [2] 00 [3] 00 00 10 40 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D }

	condition:
		$a0 at pe.entry_point
}
