import "pe"

rule PECompactv090
{
	meta:
		author = "malware-lu"
		description = "Detects PE files packed with PECompact v0.90"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 06 68 [2] 40 00 C3 9C 60 BD [2] 00 00 B9 02 00 00 00 B0 90 8D BD 7A 42 40 00 F3 AA 01 AD D9 43 40 00 FF B5 }

	condition:
		$a0 at pe.entry_point
}
