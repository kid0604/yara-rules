import "pe"

rule EXECryptorv1401
{
	meta:
		author = "malware-lu"
		description = "Detects EXECryptor v1.401 encrypted files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 [2] 00 31 C0 89 41 14 89 41 18 80 }

	condition:
		$a0 at pe.entry_point
}
