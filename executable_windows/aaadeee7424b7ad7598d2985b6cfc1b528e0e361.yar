import "pe"

rule RCryptorv11Vaska
{
	meta:
		author = "malware-lu"
		description = "Detects RCryptor v1.1 Vaska malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B 04 24 83 E8 4F 68 [4] FF D0 }
		$a1 = { 8B 04 24 83 E8 4F 68 [4] FF D0 B8 [4] 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 or $a1
}
