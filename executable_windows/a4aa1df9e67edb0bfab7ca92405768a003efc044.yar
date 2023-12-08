import "pe"

rule yoda_crypter_1_3 : Crypter
{
	meta:
		author = "Kevin Falcoz"
		date_create = "15/04/2013"
		description = "Yoda Crypter 1.3"
		os = "windows"
		filetype = "executable"

	strings:
		$signature1 = {55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 00 B9 5D 34 40 00 81 E9 C6 28 40 00 8B D5 81 C2 C6 28 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC}

	condition:
		$signature1 at pe.entry_point
}
