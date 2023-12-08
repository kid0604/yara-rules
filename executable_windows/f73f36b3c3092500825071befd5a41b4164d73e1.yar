import "pe"

rule IMPLANT_2_v18
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
		$STR1 = { 8A C1 02 C0 8D 1C 08 8B 45 F8 02 DB 8D 4A 02 8B 55 0C 88 5D FF
         8B 5D EC 83 C2 FE 03 D8 89 55 E0 89 5D DC 8D 49 00 03 C1 8D 34 0B 0F
         B6 1C 0A 0F AF D8 33 D2 8D 41 FF F7 75 F4 8B 45 0C C1 EB 07 8D 79 01
         32 1C 02 33 D2 8B C7 89 5D E4 BB 06 00 00 00 F7 F3 8B 45 0C 8D 59 FE
         02 5D FF 32 1C 02 8B C1 33 D2 B9 06 00 00 00 F7 F1 8B 45 0C 8B CF 22
         1C 02 8B 45 E4 8B 55 E0 02 C3 30 06 8B 5D DC 8D 41 FE 83 F8 06 8B 45
         F8 72 9B 8B 4D F0 8B 5D D8 8B 7D 08 8B F0 41 83 C6 06 89 4D F0 89 75
         F8 3B 4D D4 0F 82 ?? ?? ?? ?? 8B 55 E8 3B CB 75 09 8D 04 5B 03 C0 2B
         F8 EB 02 33 FF 3B FA 0F 83 ?? ?? ?? ?? 8B 5D EC 8A C1 02 C0 83 C3 FE
         8D 14 08 8D 04 49 02 D2 03 C0 88 55 0B 8D 48 FE 8D 57 02 03 C3 89 4D
         D4 8B 4D 0C 89 55 F8 89 45 D8 EB 06 8D 9B 00 00 00 00 0F B6 5C 0A FE
         8D 34 02 8B 45 D4 03 C2 0F AF D8 8D 7A 01 8D 42 FF 33 D2 F7 75 F4 C1
         EB 07 8B C7 32 1C 0A 33 D2 B9 06 00 00 00 F7 F1 8A 4D F8 8B 45 0C 80
         E9 02 02 4D 0B 32 0C 02 8B 45 F8 33 D2 F7 75 F4 8B 45 0C 22 0C 02 8B
         D7 02 D9 30 1E 8B 4D 0C 8D 42 FE 3B 45 E8 }

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
