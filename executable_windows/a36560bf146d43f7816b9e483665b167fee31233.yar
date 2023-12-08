import "pe"

rule EXECryptorv151x
{
	meta:
		author = "malware-lu"
		description = "Detects the EXECryptor v1.51x malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 24 [3] 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 [7] 31 C0 89 41 14 89 41 18 80 A1 C1 [3] FE C3 31 C0 64 FF 30 64 89 20 CC C3 }

	condition:
		$a0 at pe.entry_point
}
