import "pe"

rule EXECryptor239DLLminimumprotection
{
	meta:
		author = "malware-lu"
		description = "Detects EXECryptor 2.39 DLL with minimum protection"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 51 68 [4] 87 2C 24 8B CD 5D 81 E1 [4] E9 [3] 00 89 45 F8 51 68 [4] 59 81 F1 [4] 0B 0D [4] 81 E9 [4] E9 [3] 00 81 C2 [4] E8 [3] 00 87 0C 24 59 51 64 8B 05 30 00 00 00 8B 40 0C 8B 40 0C E9 [3] 00 F7 D6 2B D5 E9 [3] 00 87 3C 24 8B CF 5F 87 14 24 1B CA E9 [3] 00 83 C4 08 68 [4] E9 [3] 00 C3 E9 [3] 00 E9 [3] 00 50 8B C5 87 04 24 8B EC 51 0F 88 [3] 00 FF 05 [4] E9 [3] 00 87 0C 24 59 99 03 04 24 E9 [3] 00 C3 81 D5 [4] 9C E9 [3] 00 81 FA [4] E9 [3] 00 C1 C3 15 81 CB [4] 81 F3 [4] 81 C3 [4] 87 }

	condition:
		$a0 at pe.entry_point
}
