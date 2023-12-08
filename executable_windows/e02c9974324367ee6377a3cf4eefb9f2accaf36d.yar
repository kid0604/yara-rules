import "pe"

rule ThinstallEmbedded20XJitit
{
	meta:
		author = "malware-lu"
		description = "Detects ThinstallEmbedded20XJitit malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 EF BE AD DE 50 6A 00 FF 15 [4] E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 }

	condition:
		$a0 at pe.entry_point
}
