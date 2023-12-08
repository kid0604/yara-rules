import "pe"

rule kkrunchy023alphaRyd
{
	meta:
		author = "malware-lu"
		description = "Detects kkrunchy023alphaRyd malware based on entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BD 08 [2] 00 C7 45 00 [3] 00 FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF [3] 00 57 BE [3] 00 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 10 C9 73 F3 FF 45 0C 91 AA 83 C9 FF 8D 5C 8D 18 FF D6 74 DD E3 17 8D 5D 1C FF D6 74 10 8D 9D A0 08 00 00 E8 ?? 00 00 00 8B 45 10 EB 42 8D 9D A0 04 00 00 E8 ?? 00 00 00 49 49 78 40 8D 5D 20 74 03 83 C3 40 31 D2 42 E8 ?? 00 00 00 8D 0C 48 F6 C2 10 74 F3 41 91 8D 9D A0 08 00 00 E8 ?? 00 00 00 3D 00 08 00 00 83 D9 FF 83 F8 60 83 D9 FF 89 45 10 56 89 FE 29 C6 F3 A4 5E EB 90 BE [3] 00 BB [3] 00 55 46 AD 85 C0 74 ?? 97 56 FF 13 85 C0 74 16 95 AC 84 C0 75 FB 38 06 74 E8 78 ?? 56 55 FF 53 04 AB 85 C0 }

	condition:
		$a0 at pe.entry_point
}
