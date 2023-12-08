import "pe"

rule EXECryptor2223compressedcodewwwstrongbitcom
{
	meta:
		author = "malware-lu"
		description = "Detects compressed code in files encrypted with EXECryptor version 2.2.23 from www.strongbit.com"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 58 [5] 8B 1C 24 81 EB [4] B8 [4] 50 6A 04 68 00 10 00 00 50 6A 00 B8 C4 [3] 8B 04 18 FF D0 59 BA [4] 01 DA 52 53 50 89 C7 89 D6 FC F3 A4 B9 [4] 01 D9 FF D1 58 8B 1C 24 68 00 80 00 00 6A 00 50 }
		$a1 = { E8 00 00 00 00 58 [5] 8B 1C 24 81 EB [4] B8 [4] 50 6A 04 68 00 10 00 00 50 6A 00 B8 C4 [3] 8B 04 18 FF D0 59 BA [4] 01 DA 52 53 50 89 C7 89 D6 FC F3 A4 B9 [4] 01 D9 FF D1 58 8B 1C 24 68 00 80 00 00 6A 00 50 B8 C8 [3] 8B 04 18 FF D0 59 58 5B 83 EB 05 C6 03 B8 43 89 03 83 C3 04 C6 03 C3 09 C9 74 46 89 C3 E8 A0 00 00 00 FC AD 83 F8 FF 74 38 53 89 CB 01 C3 01 0B 83 C3 04 AC 3C FE 73 07 25 FF 00 00 00 EB ED 81 C3 FE 00 00 00 09 C0 7A 09 66 AD 25 FF FF 00 00 EB DA AD 4E 25 FF FF FF 00 3D FF FF FF 00 75 CC [5] C3 }

	condition:
		$a0 or $a1
}
