rule Malwareusedbycyberthreatactor1
{
	meta:
		description = "Detects the presence of malware used by cyber threat actor 1"
		os = "windows"
		filetype = "executable"

	strings:
		$heapCreateFunction_0 = {33C06A003944240868001000000F94C050FF15????????85C0A3???????07436E893FEFFFF83F803A3???????0750D68F8030000E8??00000059EB0A83F8027518E8????000085C0750FFF35???????0FF15???????033C0C36A0158C3}
		$heapCreateFunction = { 55 8B EC B8 2C 12 00 00 E8 ?? ?? FF FF 8D 85 68 FF FF FF 53 50 C7 85 68 FF FF FF 94 00 00 00 FF 1? ?? ?? ?? ?0 85 C0 74 1A 83 BD 78 FF FF FF 02 75 11 83 BD 6C FF FF FF 05 72 08 6A 01 58 E9 02 01 00 00 8D 85 D4 ED FF F6 89 01 00 00 05 06 8? ?? ?? ?? 0F F1 5? ?? ?? ?? 08 5C 00 F8 4D 00 00 00 03 3D B8 D8 DD 4E DF FF F3 89 DD DF FF F7 41 38 A0 13 C6 17 C0 83 C7 A7 F0 42 C2 08 80 14 13 81 97 5E D8 D8 5D 4E DF FF F6 A1 65 06 8? ?? ?? ?? 0E 8? ?? ?0 00 08 3C 40 C8 5C 07 50 88 D8 5D 4E DF FF FE B4 98 D8 56 4F EF FF F6 80 40 10 00 05 05 3F F1 5? ?? ?? ?? 03 89 D6 4F EF FF F8 D8 D6 4F EF FF F7 41 38 A0 13 C6 17 C0 83 C7 A7 F0 42 C2 08 80 14 13 81 97 5E D8 D8 56 4F EF FF F5 08 D8 5D 4E DF FF F5 0E 8? ?? ?? ?? ?5 95 93 BC 37 43 E6 A2 C5 0E 8? ?? ?? ?? ?5 93 BC 35 97 43 04 08 BC 83 81 87 40 E8 03 93 B7 50 48 81 9E B0 14 13 81 97 5F 26 A0 A5 35 0E 8? ?? ?0 00 08 3C 40 C8 3F 80 27 41 D8 3F 80 37 41 88 3F 80 17 41 38 D4 5F C5 0E 89 8F EF FF F8 07 DF C0 65 91 BC 08 3C 00 35 BC 9C}
		$getMajorMinorLinker = {568B7424086A00832600FF15???????06681384D5A75148B483C85C9740D03C18A481A880E8A401B8846015EC3}
		$openServiceManager = {FF15???0?0?08B?885??74????????????????5?FF15???0?0?08B?????0?0?08BF?85F?74}

	condition:
		all of them
}
