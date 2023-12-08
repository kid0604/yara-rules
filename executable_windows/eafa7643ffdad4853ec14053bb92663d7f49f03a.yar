import "pe"

rule ENIGMAProtectorSukhovVladimir
{
	meta:
		author = "malware-lu"
		description = "Detects ENIGMA Protector packed files by Sukhov Vladimir"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 45 6E 69 67 6D 61 20 70 72 6F 74 65 63 74 6F 72 20 76 31 }

	condition:
		$a0
}
