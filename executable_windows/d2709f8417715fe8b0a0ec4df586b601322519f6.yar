import "pe"

rule hmimysProtectv10
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of hmimysProtectv10 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 BA 00 00 00 ?? 00 00 00 00 [2] 00 00 10 40 00 [3] 00 [3] 00 00 [2] 00 [3] 00 [3] 00 [3] 00 [3] 00 [3] 00 ?? 00 00 00 00 00 00 00 [3] 00 00 00 00 00 00 00 00 00 [3] 00 [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [3] 00 [3] 00 [3] 00 [3] 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 00 00 AD 8B DE 8B F0 83 C3 44 AD 85 C0 74 32 8B F8 56 FF 13 8B E8 AC 84 C0 75 FB AC 84 C0 74 EA 4E AD A9 }
		$a1 = { E8 BA 00 00 00 ?? 00 00 00 00 [2] 00 00 10 40 00 [3] 00 [3] 00 00 [2] 00 [3] 00 [3] 00 [3] 00 [3] 00 [3] 00 ?? 00 00 00 00 00 00 00 [3] 00 00 00 00 00 00 00 00 00 [3] 00 [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [3] 00 [3] 00 [3] 00 [3] 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 00 00 AD 8B DE 8B F0 83 C3 44 AD 85 C0 74 32 8B F8 56 FF 13 8B E8 AC 84 C0 75 FB AC 84 C0 74 EA 4E AD A9 00 00 00 }

	condition:
		$a0 at pe.entry_point or $a1
}
