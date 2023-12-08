import "pe"

rule yoda_crypter_1_2 : Crypter
{
	meta:
		author = "Kevin Falcoz"
		date_create = "15/04/2013"
		description = "Yoda Crypter 1.2"
		os = "windows"
		filetype = "executable"

	strings:
		$signature1 = {60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC [19] EB 01 [27] AA E2 CC}

	condition:
		$signature1 at pe.entry_point
}
