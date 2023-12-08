import "pe"

rule EnigmaProtector10XSukhovVladimir
{
	meta:
		author = "malware-lu"
		description = "Detects Enigma Protector 1.0 by Sukhov Vladimir"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 [2] 81 ED [35] E8 01 00 00 00 ?? 83 C4 04 EB 02 [2] 60 E8 24 00 00 00 00 00 ?? EB 02 [2] 8B 44 24 0C 83 80 B8 00 00 00 03 31 C0 C3 83 C0 08 EB 02 [2] 89 C4 61 EB 2E [7] EB 01 ?? 31 C0 EB 01 ?? 64 FF 30 EB 01 ?? 64 89 20 EB 02 [2] 89 00 9A 64 8F 05 00 00 00 00 EB 02 C1 ?? 58 61 EB 01 }

	condition:
		$a0
}
