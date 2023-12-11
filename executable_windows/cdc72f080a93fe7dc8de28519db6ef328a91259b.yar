import "pe"

rule IMPLANT_2_v9
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
		$STR1 = { 8A C3 02 C0 02 D8 8B 45 F8 02 DB 83 C1 02 03 45 08 88 5D 0F 89
         45 E8 8B FF 0F B6 5C 0E FE 8B 45 F8 03 C1 0F AF D8 8D 51 01 89 55 F4
         33 D2 BF 06 00 00 00 8D 41 FF F7 F7 8B 45 F4 C1 EB 07 32 1C 32 33 D2
         F7 F7 8A C1 02 45 0F 2C 02 32 04 32 33 D2 88 45 FF 8B C1 8B F7 F7 F6
         8A 45 FF 8B 75 14 22 04 32 02 D8 8B 45 E8 30 1C 08 8B 4D F4 8D 51 FE
         3B D7 72 A4 8B 45 E4 8B 7D E0 8B 5D F0 83 45 F8 06 43 89 5D F0 3B D8
         0F 82 ?? ?? ?? ?? 3B DF 75 13 8D 04 7F 8B 7D 10 03 C0 2B F8 EB 09 33
         C9 E9 5B FF FF FF 33 FF 3B 7D EC 0F 83 ?? ?? ?? ?? 8B 55 08 8A CB 02
         C9 8D 04 19 02 C0 88 45 13 8D 04 5B 03 C0 8D 54 10 FE 89 45 E0 8D 4F
         02 89 55 E4 EB 09 8D 9B 00 00 00 00 8B 45 E0 0F B6 5C 31 FE 8D 44 01
         FE 0F AF D8 8D 51 01 89 55 0C 33 D2 BF 06 00 00 00 8D 41 FF F7 F7 8B
         45 0C C1 EB 07 32 1C 32 33 D2 F7 F7 8A C1 02 45 13 2C 02 32 04 32 33
         D2 88 45 0B 8B C1 8B F7 F7 F6 8A 45 0B 8B 75 14 22 04 32 02 D8 8B 45
         E4 30 1C 01 8B 4D 0C }

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
