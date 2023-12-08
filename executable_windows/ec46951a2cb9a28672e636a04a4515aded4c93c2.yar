import "pe"

rule PEEncrypt10Liwuyue
{
	meta:
		author = "malware-lu"
		description = "Detects the PEEncrypt10Liwuyue malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D 0F 05 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89 5D EC 8B 41 18 8B C8 49 85 C9 72 5A 41 33 C0 8B D8 C1 E3 02 03 DA 8B 3B 03 3E 81 3F 47 65 74 50 75 40 8B DF 83 C3 04 81 3B 72 6F 63 41 75 33 8B DF 83 C3 08 81 3B 64 64 72 65 75 26 83 C7 0C 66 81 3F 73 73 }

	condition:
		$a0 at pe.entry_point
}
