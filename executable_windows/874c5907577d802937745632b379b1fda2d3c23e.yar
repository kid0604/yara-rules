import "pe"

rule StonesPEEncryptorv113
{
	meta:
		author = "malware-lu"
		description = "Detects the StonesPEEncryptorv113 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 57 56 52 51 53 E8 [4] 5D 8B D5 81 ED 97 3B 40 ?? 2B 95 2D 3C 40 ?? 83 EA 0B 89 95 36 3C 40 ?? 01 95 24 3C 40 ?? 01 95 28 }

	condition:
		$a0 at pe.entry_point
}
