import "pe"

rule ZealPack10Zeal
{
	meta:
		author = "malware-lu"
		description = "Detects ZealPack version 10 Zeal malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { C7 45 F4 00 00 40 00 C7 45 F0 [4] 8B 45 F4 05 [4] 89 45 F4 C7 45 FC 00 00 00 00 EB 09 8B 4D FC 83 C1 01 89 4D FC 8B 55 FC 3B 55 F0 7D 22 8B 45 F4 03 45 FC 8A 08 88 4D F8 0F BE 55 F8 83 F2 0F 88 55 F8 8B 45 F4 03 45 FC 8A 4D F8 88 08 EB CD FF 65 F4 }

	condition:
		$a0 at pe.entry_point
}
