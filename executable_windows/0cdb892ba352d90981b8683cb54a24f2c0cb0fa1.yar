import "pe"

rule EXECryptorv13045
{
	meta:
		author = "malware-lu"
		description = "Detects EXECryptor v1.30.45 encrypted files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 [7] 31 C0 89 41 14 89 41 18 80 A1 }
		$a1 = { E8 24 [3] 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 [7] 31 C0 89 41 14 89 41 18 80 A1 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
