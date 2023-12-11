import "pe"

rule CExev10a
{
	meta:
		author = "malware-lu"
		description = "Detects a specific code pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 81 EC 0C 02 [2] 56 BE 04 01 [2] 8D 85 F8 FE FF FF 56 50 6A ?? FF 15 54 10 40 ?? 8A 8D F8 FE FF FF 33 D2 84 C9 8D 85 F8 FE FF FF 74 16 }

	condition:
		$a0 at pe.entry_point
}
