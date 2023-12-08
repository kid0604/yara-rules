import "pe"

rule MacromediaWindowsFlashProjectorPlayerv40
{
	meta:
		author = "malware-lu"
		description = "Detects Macromedia Windows Flash Projector Player v4.0"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 EC 44 56 FF 15 24 41 43 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C }

	condition:
		$a0 at pe.entry_point
}
