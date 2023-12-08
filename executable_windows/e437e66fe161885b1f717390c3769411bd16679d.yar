import "pe"

rule RCryptorv15Vaska
{
	meta:
		author = "malware-lu"
		description = "Detects RCryptor v1.5 Vaska malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 2C 24 4F 68 [4] FF 54 24 04 83 44 24 04 4F }

	condition:
		$a0 at pe.entry_point
}
