import "pe"

rule PAVCryptorPawningAntiVirusCryptormasha_dev
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting PAVCryptorPawningAntiVirusCryptormasha_dev malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 53 56 57 55 BB 2C [2] 70 BE 00 30 00 70 BF 20 [2] 70 80 7B 28 00 75 16 83 3F 00 74 11 8B 17 89 D0 33 D2 89 17 8B E8 FF D5 83 3F 00 75 EF 83 3D 04 30 00 70 00 74 06 FF 15 54 30 00 70 80 7B 28 02 75 0A 83 3E 00 75 05 33 C0 89 43 0C FF 15 1C 30 00 70 80 7B 28 01 76 05 83 3E 00 74 22 8B 43 10 85 C0 74 1B FF 15 14 30 00 70 8B 53 10 8B 42 10 3B 42 04 74 0A 85 C0 74 06 50 E8 8F FA FF FF FF 15 20 30 00 70 80 7B 28 01 75 03 FF 53 24 80 7B 28 00 74 05 E8 35 FF FF FF 83 3B 00 75 17 83 3D 10 [2] 70 00 74 06 FF 15 10 [2] 70 8B 06 50 E8 A9 FA FF FF 8B 03 56 8B F0 8B FB B9 0B 00 00 00 F3 A5 5E E9 73 FF FF FF 5D 5F 5E 5B C3 A3 00 30 00 70 E8 26 FF FF FF C3 90 8F 05 04 30 00 70 E9 E9 FF FF FF C3 }

	condition:
		$a0
}
