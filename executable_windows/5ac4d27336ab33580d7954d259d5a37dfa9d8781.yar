import "pe"

rule RECryptv07xCruddRETh2
{
	meta:
		author = "malware-lu"
		description = "Detects a specific encryption algorithm used by a malware variant"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 [2] 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B 17 33 55 58 89 17 83 C7 04 83 C1 FC EB EC 8B }

	condition:
		$a0 at pe.entry_point
}
