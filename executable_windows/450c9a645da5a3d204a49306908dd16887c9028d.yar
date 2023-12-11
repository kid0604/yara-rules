import "pe"

rule ENIGMAProtectorV112SukhovVladimir
{
	meta:
		author = "malware-lu"
		description = "Detects ENIGMA Protector v1.12 by Sukhov Vladimir"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 C5 FA 81 ED [3] 00 [31] E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 }

	condition:
		$a0 at pe.entry_point
}
