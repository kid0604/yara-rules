import "pe"

rule IMPLANT_4_v1
{
	meta:
		description = "BlackEnergy / Voodoo Bear Implant by APT28"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		date = "2017-02-10"
		score = 85
		os = "windows"
		filetype = "executable"

	strings:
		$STR1 = {55 8B EC 81 EC 54 01 00 00 83 65 D4 00 C6 45 D8 61 C6 45 D9 64
         C6 45 DA 76 C6 45 DB 61 C6 45 DC 70 C6 45 DD 69 C6 45 DE 33 C6 45 DF
         32 C6 45 E0 2EE9 ?? ?? ?? ??}
		$STR2 = {C7 45 EC 5A 00 00 00 C7 45 E0
            46 00 00 00 C7 45 E8 5A 00 00 00 C7 45 E4 46 00 00 00}

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and 1 of them
}
