import "pe"

rule RCryptor20Vaska
{
	meta:
		author = "malware-lu"
		description = "Detects the RCryptor 2.0 Vaska malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 [4] F7 D1 83 F1 FF }

	condition:
		$a0 at pe.entry_point
}
