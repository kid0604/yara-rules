import "pe"

rule ReflexiveArcadeWrapper
{
	meta:
		author = "malware-lu"
		description = "Detects Reflexive Arcade wrapper malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 98 68 42 00 68 14 FA 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 F8 50 42 00 33 D2 8A D4 89 15 3C E8 42 00 8B C8 81 E1 FF 00 00 00 89 0D 38 E8 42 00 C1 E1 08 03 CA 89 0D 34 E8 42 00 C1 E8 10 A3 30 E8 }

	condition:
		$a0 at pe.entry_point
}
