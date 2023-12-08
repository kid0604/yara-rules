import "pe"

rule StonesPEEncryptorv10
{
	meta:
		author = "malware-lu"
		description = "Detects the StonesPEEncryptorv10 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 57 56 52 51 53 E8 [4] 5D 8B D5 81 ED 63 3A 40 ?? 2B 95 C2 3A 40 ?? 83 EA 0B 89 95 CB 3A 40 ?? 8D B5 CA 3A 40 ?? 0F B6 36 }

	condition:
		$a0 at pe.entry_point
}
