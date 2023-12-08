import "pe"

rule MacromediaWindowsFlashProjectorPlayerv30
{
	meta:
		author = "malware-lu"
		description = "Detects Macromedia Windows Flash Projector Player v3.0"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 EC 44 56 FF 15 94 13 42 00 8B F0 B1 22 8A 06 3A C1 75 13 8A 46 01 46 3A C1 74 04 84 C0 75 F4 38 0E 75 0D 46 EB 0A 3C 20 7E 06 }

	condition:
		$a0 at pe.entry_point
}
