import "pe"

rule EXECryptor2117StrongbitSoftCompleteDevelopment
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the EXECryptor 2.1.17 StrongbitSoft Complete Development packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE [4] B8 00 00 [2] 89 45 FC 89 C2 8B 46 0C 09 C0 0F 84 ?? 00 00 00 01 D0 89 C3 50 FF 15 94 [3] 09 C0 0F 85 0F 00 00 00 53 FF 15 98 [3] 09 C0 0F 84 ?? 00 00 00 89 45 F8 6A 00 8F 45 F4 8B 06 09 C0 8B 55 FC 0F 85 03 00 00 00 8B 46 10 01 }

	condition:
		$a0
}
