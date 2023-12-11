import "pe"

rule EXECryptor2223protectedIAT
{
	meta:
		author = "malware-lu"
		description = "Detects files protected with EXECryptor and containing Import Address Table (IAT) manipulation"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { CC [3] 00 00 00 00 FF FF FF FF 3C [3] B4 [3] 08 [3] 00 00 00 00 FF FF FF FF E8 [3] 04 [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 [24] 4C [3] 60 [3] 70 [3] 84 [3] 94 [3] A4 [3] 00 00 00 00 75 73 65 72 33 32 2E 64 6C 6C 00 00 00 00 4D 65 73 73 61 67 65 42 6F 78 }

	condition:
		$a0
}
