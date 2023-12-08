import "pe"

rule ENIGMAProtectorV11V12SukhovVladimir
{
	meta:
		author = "malware-lu"
		description = "Detects ENIGMA Protector v1.1 and v1.2 by Sukhov Vladimir"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 81 }

	condition:
		$a0 at pe.entry_point
}
