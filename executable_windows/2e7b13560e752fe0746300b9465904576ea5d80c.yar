import "pe"

rule EXECryptor239minimumprotection
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting files protected with EXECryptor 2.39 minimum protection"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 [4] E9 [3] FF 50 C1 C8 18 89 05 [4] C3 C1 C0 18 51 E9 [3] FF 84 C0 0F 84 6A F9 FF FF E9 [3] FF C3 E9 [3] FF E8 CF E9 FF FF B8 01 00 00 00 E9 [3] FF 2B D0 68 A0 36 80 D4 59 81 C9 64 98 FF 99 E9 [3] FF 84 C0 0F 84 8E EC FF FF E9 [3] FF C3 87 3C 24 5F 8B 00 03 45 FC 83 C0 18 E9 [3] FF 87 0C 24 59 B8 01 00 00 00 D3 E0 23 D0 E9 02 18 00 00 0F 8D DB 00 00 00 C1 E8 14 E9 CA 00 00 00 9D 87 0C 24 59 87 1C 24 68 AE 73 B9 96 E9 C5 10 00 00 0F 8A [4] E9 [3] FF 81 FD F5 FF 8F 07 E9 4F 10 00 00 C3 E9 5E 12 00 00 87 3C 24 E9 [3] FF E8 [3] FF 83 3D [4] 00 0F 85 [4] 8D 55 EC B8 [4] E9 [3] FF E8 A7 1A 00 00 E8 2A CB FF FF E9 [3] FF C3 E9 [3] FF 59 89 45 E0 }

	condition:
		$a0 at pe.entry_point
}
