import "pe"

rule Armadillov200b2200b3
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillov200b2200b3 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 00 F2 40 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}
