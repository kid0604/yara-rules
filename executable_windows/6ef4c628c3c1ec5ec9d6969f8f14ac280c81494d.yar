import "pe"

rule EXECryptorvxxxx
{
	meta:
		author = "malware-lu"
		description = "Detects EXECryptorvxxxx malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 24 [3] 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 [7] 31 C0 89 41 }

	condition:
		$a0 at pe.entry_point
}
