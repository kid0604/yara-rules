import "pe"

rule NJoy11NEX
{
	meta:
		author = "malware-lu"
		description = "Detects NJoy11NEX malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 0C 3C 40 00 E8 24 FC FF FF 6A 00 68 28 3A 40 00 6A 0A 6A 00 E8 D8 FC FF FF E8 7F F5 FF FF 8D 40 00 }

	condition:
		$a0 at pe.entry_point
}
