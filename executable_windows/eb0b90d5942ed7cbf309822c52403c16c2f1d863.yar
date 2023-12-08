import "pe"

rule ENIGMAProtectorV11SukhovVladimir
{
	meta:
		author = "malware-lu"
		description = "Detects ENIGMA Protector v1.1 by Sukhov Vladimir"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 [2] 81 }

	condition:
		$a0 at pe.entry_point
}
