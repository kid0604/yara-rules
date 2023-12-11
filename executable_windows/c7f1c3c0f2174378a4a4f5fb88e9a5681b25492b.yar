import "pe"

rule Armadillov220b1
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillo v2.20b1 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 30 12 41 00 68 A4 A5 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}
