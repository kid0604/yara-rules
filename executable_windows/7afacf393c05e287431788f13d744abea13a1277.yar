import "pe"

rule RCryptorv20HideEPVaska
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RCryptor v2.0 malware by hiding entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 DC 20 ?? 00 F7 D1 83 F1 FF E8 00 00 00 00 F7 D1 83 F1 FF C3 }

	condition:
		$a0 at pe.entry_point
}
