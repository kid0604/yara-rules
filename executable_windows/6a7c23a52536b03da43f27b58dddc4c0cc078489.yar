import "pe"

rule yzpackV11UsAr
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of yzpackV11UsAr malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 33 C0 8D 48 07 50 E2 FD 8B EC 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 8D 40 7C 8B 40 3C 89 45 04 E8 F3 07 00 00 60 8B 5D 04 8B 73 3C 8B 74 33 78 03 F3 56 8B 76 20 03 F3 33 C9 49 92 41 AD 03 C3 52 33 FF 0F B6 10 38 F2 }

	condition:
		$a0 at pe.entry_point
}
