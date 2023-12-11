import "pe"

rule IMPLANT_2_v20
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
		$func = { 0F B6 5C 0A FE 8D 34 02 8B 45 D4 03 C2 0F AF D8 8D 7A 01 8D 42
         FF 33 D2 F7 75 F4 C1 EB 07 8B C7 32 1C 0A 33 D2 B9 06 00 00 00 F7 F1
         8A 4D F8 8B 45 0C 80 E9 02 02 4D 0B 32 0C 02 8B 45 F8 33 D2 F7 75 F4
         8B 45 0C 22 0C 02 8B D7 02 D9 30 1E 8B 4D 0C 8D 42 FE 3B 45 E8 8B 45
         D8 89 55 F8 72 A0 }

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
