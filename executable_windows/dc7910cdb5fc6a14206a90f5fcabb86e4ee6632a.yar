import "pe"

rule NJoy12NEX
{
	meta:
		author = "malware-lu"
		description = "Detects NJoy12NEX malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 A4 32 40 00 E8 E8 F1 FF FF 6A 00 68 54 2A 40 00 6A 0A 6A 00 E8 A8 F2 FF FF E8 C7 EA FF FF 8D 40 00 }

	condition:
		$a0 at pe.entry_point
}
