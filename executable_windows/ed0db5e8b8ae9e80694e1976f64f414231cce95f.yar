import "pe"

rule RCryptorv13v14Vaska
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting RCryptor v1.3 and v1.4 malware variants"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 8B 44 24 04 83 E8 4F 68 [4] FF D0 58 59 50 }
		$a1 = { 55 8B EC 8B 44 24 04 83 E8 4F 68 [4] FF D0 58 59 50 B8 [4] 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
