import "pe"

rule MacromediaWindowsFlashProjectorPlayerv50
{
	meta:
		author = "malware-lu"
		description = "Detects Macromedia Windows Flash Projector Player version 5.0"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 EC 44 56 FF 15 70 61 44 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C 3C 20 7E 08 8A 46 01 46 3C 20 7F F8 8A 06 84 C0 74 0C 3C 20 7F 08 8A 46 01 46 84 C0 75 F4 8D 44 24 04 C7 44 24 30 00 }

	condition:
		$a0 at pe.entry_point
}
