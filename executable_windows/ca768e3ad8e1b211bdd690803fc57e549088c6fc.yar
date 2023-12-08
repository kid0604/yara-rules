import "pe"

rule Armadillov201
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillov201 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 08 02 41 00 68 04 9A 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}
