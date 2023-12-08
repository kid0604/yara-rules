import "pe"

rule Vpackerttui
{
	meta:
		author = "malware-lu"
		description = "Detects Vpackerttui malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 89 C6 C7 45 E0 01 00 00 00 F7 03 00 00 FF FF 75 18 0F B7 03 50 8B 45 D8 50 FF 55 F8 89 07 8B C3 E8 ?? FE FF FF 8B D8 EB 13 53 8B 45 D8 50 FF 55 F8 89 07 8B C3 E8 ?? FE FF FF 8B D8 83 C7 04 FF 45 E0 4E 75 C4 8B F3 83 3E 00 75 88 8B 45 E4 8B 40 10 03 45 DC 8B 55 14 83 C2 20 89 02 68 00 80 00 00 6A 00 8B 45 D4 50 FF 55 EC 8B 55 DC 8B 42 3C 03 45 DC 83 C0 04 8B D8 83 C3 14 8D 45 E0 50 6A 40 68 00 10 00 00 52 FF 55 E8 8D 43 60 }

	condition:
		$a0
}
