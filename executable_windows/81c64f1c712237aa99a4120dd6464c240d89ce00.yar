import "pe"

rule Armadillov184
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillov184 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 E8 C1 40 00 68 F4 86 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}
