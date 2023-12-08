import "pe"

rule Armadillo440SiliconRealmsToolworks
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillo440SiliconRealmsToolworks malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 31 2E 31 2E 34 00 00 00 C2 E0 94 BE 93 FC DE C6 B6 24 83 F7 D2 A4 92 77 40 27 CF EB D8 6F 50 B4 B5 29 24 FA 45 08 04 52 D5 1B D2 8C 8A 1E 6E FF 8C 5F 42 89 F1 83 B1 27 C5 69 57 FC 55 0A DD 44 BE 2A 02 97 6B 65 15 AA 31 E9 28 7D 49 1B DF B5 5D 08 A8 BA A8 }

	condition:
		$a0
}
