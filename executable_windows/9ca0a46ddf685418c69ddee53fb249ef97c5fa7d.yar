import "pe"

rule EXECryptor226minimumprotection
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting EXECryptor 2.26 minimum protection"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 68 [4] 58 81 E0 [4] E9 [3] 00 87 0C 24 59 E8 [3] 00 89 45 F8 E9 [4] 0F 83 [3] 00 E9 [4] 87 14 24 5A 57 68 [4] E9 [4] 58 81 C0 [4] 2B 05 [4] 81 C8 [4] 81 E0 [4] E9 [3] 00 C3 E9 [4] C3 BF [4] 81 CB [4] BA [4] 52 E9 [3] 00 E8 [3] 00 E9 [3] 00 E9 [4] 87 34 24 5E 66 8B 00 66 25 [2] E9 [4] 8B CD 87 0C 24 8B EC 51 89 EC 5D 8B 05 [4] 09 C0 E9 [4] 59 81 C1 [4] C1 C1 ?? 23 0D [4] 81 F9 [4] E9 [4] C3 E9 [3] 00 13 D0 0B F9 E9 [4] 51 E8 [4] 8B 64 24 08 31 C0 64 8F 05 00 00 00 00 5A E9 [4] 3C A4 0F 85 [3] 00 8B 45 FC 66 81 38 [2] 0F 84 05 00 00 00 E9 [4] 0F 84 [4] E9 [4] 87 3C 24 5F 31 DB 31 C9 31 D2 68 [4] E9 [4] 89 45 FC 33 C0 89 45 F4 83 7D FC 00 E9 [4] 53 52 8B D1 87 14 24 81 C0 [4] 0F 88 [4] 3B CB }

	condition:
		$a0 at pe.entry_point
}
