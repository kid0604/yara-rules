import "pe"

rule RCryptorv16xVaska
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RCryptor v1.6 malware variant Vaska"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 [4] C3 }

	condition:
		$a0 at pe.entry_point
}
