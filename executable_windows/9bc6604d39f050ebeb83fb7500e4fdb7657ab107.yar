import "pe"

rule EXECryptor2021protectedIAT
{
	meta:
		author = "malware-lu"
		description = "Detects files protected with EXECryptor 2021 and containing Import Address Table (IAT) manipulation"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { A4 [3] 00 00 00 00 FF FF FF FF 3C [3] 94 [3] D8 [3] 00 00 00 00 FF FF FF FF B8 [3] D4 [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 [19] 00 60 [3] 70 [3] 84 [3] 00 00 00 00 75 73 65 72 33 32 2E 64 6C 6C 00 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 }

	condition:
		$a0
}
