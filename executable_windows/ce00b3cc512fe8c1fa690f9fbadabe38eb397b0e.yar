import "pe"

rule EXECryptor226DLLminimumprotection
{
	meta:
		author = "malware-lu"
		description = "Yara rule to detect EXECryptor 2.26 DLL with minimum protection"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 8B C6 87 04 24 68 [4] 5E E9 [4] 85 C8 E9 [4] 81 C3 [4] 0F 81 [3] 00 81 FA [4] 33 D0 E9 [3] 00 0F 8D [3] 00 81 D5 [4] F7 D1 0B 15 [4] C1 C2 ?? 81 C2 [4] 9D E9 [4] C1 E2 ?? C1 E8 ?? 81 EA [4] 13 DA 81 E9 [4] 87 04 24 8B C8 E9 [4] 55 8B EC 83 C4 F8 89 45 FC 8B 45 FC 89 45 F8 8B 45 08 E9 [4] 8B 45 E0 C6 00 00 FF 45 E4 E9 [4] FF 45 E4 E9 [3] 00 F7 D3 0F 81 [4] E9 [4] 87 34 24 5E 8B 45 F4 E8 [3] 00 8B 45 F4 8B E5 5D C3 E9 }

	condition:
		$a0 at pe.entry_point
}
