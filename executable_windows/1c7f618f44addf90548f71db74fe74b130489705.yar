import "pe"

rule SecuPackv15
{
	meta:
		author = "malware-lu"
		description = "Detects SecuPackv15 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 CC 3A 40 ?? E8 E0 FC FF FF 33 C0 55 68 EA 3C 40 ?? 64 FF 30 64 89 20 6A ?? 68 80 [3] 6A 03 6A ?? 6A 01 [3] 80 }

	condition:
		$a0 at pe.entry_point
}
