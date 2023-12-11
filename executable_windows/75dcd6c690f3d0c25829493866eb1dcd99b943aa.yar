import "pe"

rule Pe123v200644
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B C0 EB 01 34 60 EB 01 2A 9C EB 02 EA C8 E8 0F 00 00 00 EB 03 3D 23 23 EB 01 4A EB 01 5B C3 8D 40 00 53 EB 01 6C EB 01 7E EB 01 8F E8 15 01 00 00 50 E8 67 04 00 00 EB 01 9A 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10 }

	condition:
		$a0 at pe.entry_point
}
