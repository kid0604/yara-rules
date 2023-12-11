import "pe"

rule IMPLANT_2_v19
{
	meta:
		description = "CORESHELL/SOURFACE Implant by APT28"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		date = "2017-02-10"
		score = 85
		os = "windows"
		filetype = "executable"

	strings:
		$obfuscated_RSA1 = { 7C 41 B4 DB ED B0 B8 47 F1 9C A1 49 B6 57 A6 CC D6
         74 B5 52 12 4D FC B1 B6 3B 85 73 DF AB 74 C9 25 D8 3C EA AE 8F 5E D2
         E3 7B 1E B8 09 3C AF 76 A1 38 56 76 BB A0 63 B6 9E 5D 86 E4 EC B0 DC
         89 1E FA 4A E5 79 81 3F DB 56 63 1B 08 0C BF DC FC 75 19 3E 1F B3 EE
         9D 4C 17 8B 16 9D 99 C3 0C 89 06 BB F1 72 46 7E F4 0B F6 CB B9 C2 11
         BE 5E 27 94 5D 6D C0 9A 28 F2 2F FB EE 8D 82 C7 0F 58 51 03 BF 6A 8D
         CD 99 F8 04 D6 F7 F7 88 0E 51 88 B4 E1 A9 A4 3B }
		$cleartext_RSA1 = { 06 02 00 00 00 A4 00 00 52 53 41 31 00 04 00 00 01
         00 01 00 AF BD 26 C9 04 65 45 9F 0E 3F C4 A8 9A 18 C8 92 00 B2 CC 6E
         0F 2F B2 71 90 FC 70 2E 0A F0 CA AA 5D F4 CA 7A 75 8D 5F 9C 4B 67 32
         45 CE 6E 2F 16 3C F1 8C 42 35 9C 53 64 A7 4A BD FA 32 99 90 E6 AC EC
         C7 30 B2 9E 0B 90 F8 B2 94 90 1D 52 B5 2F F9 8B E2 E6 C5 9A 0A 1B 05
         42 68 6A 3E 88 7F 38 97 49 5F F6 EB ED 9D EF 63 FA 56 56 0C 7E ED 14
         81 3A 1D B9 A8 02 BD 3A E6 E0 FA 4D A9 07 5B E6 }

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and any of them
}
