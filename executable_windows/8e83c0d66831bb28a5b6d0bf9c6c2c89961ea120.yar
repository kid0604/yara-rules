import "pe"

rule Armadillov210b2
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillo v2.10b2 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 18 12 41 00 68 24 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}
