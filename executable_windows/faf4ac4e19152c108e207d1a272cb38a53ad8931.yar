import "pe"

rule yodasCrypter13AshkbizDanehkar
{
	meta:
		author = "malware-lu"
		description = "Detects Yoda's Crypter 1.3 by Ashkbiz Danehkar"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 00 B9 5D 34 40 00 81 E9 C6 28 40 00 8B D5 81 C2 C6 28 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }

	condition:
		$a0 at pe.entry_point
}
