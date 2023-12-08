import "pe"

rule EXECryptor239DLLcompressedresources
{
	meta:
		author = "malware-lu"
		description = "Detects EXECryptor 2.39 DLL with compressed resources"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 68 [4] 58 C1 C0 0F E9 [3] 00 87 04 24 58 89 45 FC E9 [3] FF FF 05 [4] E9 [3] 00 C1 C3 18 E9 [4] 8B 55 08 09 42 F8 E9 [3] FF 83 7D F0 01 0F 85 [4] E9 [3] 00 87 34 24 5E 8B 45 FC 33 D2 56 8B F2 E9 [3] 00 BA [4] E8 [3] 00 A3 [4] C3 E9 [3] 00 C3 83 C4 04 C3 E9 [3] FF 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 E8 [3] 00 E9 [3] FF C1 C2 03 81 CA [4] 81 C2 [4] 03 C2 5A E9 [3] FF 81 E7 [4] 81 EF [4] 81 C7 [4] 89 07 E9 [4] 0F 89 [4] 87 14 24 5A 50 C1 C8 10 }

	condition:
		$a0 at pe.entry_point
}
