import "pe"

rule PEPasswordv02SMTSMF
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern in the entry point of PE files that may indicate the presence of a password-protected executable"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 04 [3] 8B EC 5D C3 33 C0 5D 8B FD 81 ED 33 26 40 ?? 81 EF [4] 83 EF 05 89 AD 88 27 40 ?? 8D 9D 07 29 40 ?? 8D B5 62 28 40 ?? 46 80 }

	condition:
		$a0 at pe.entry_point
}
