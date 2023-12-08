import "pe"

rule Armadillov190c
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillov190c malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 10 F2 40 00 68 74 9D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}
