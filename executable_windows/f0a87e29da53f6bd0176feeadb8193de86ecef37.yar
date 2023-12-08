import "pe"

rule IMPLANT_3_v2
{
	meta:
		description = "X-Agent/CHOPSTICK Implant by APT28"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		date = "2017-02-10"
		score = 85
		os = "windows"
		filetype = "executable"

	strings:
		$base_key_moved = {C7 45 ?? 3B C6 73 0F C7 45 ?? 8B 07 85 C0 C7 45 ?? 74
         02 FF D0 C7 45 ?? 83 C7 04 3B C7 45 ?? FE 72 F1 5F C7 45 ?? 5E C3 8B
         FF C7 45 ?? 56 B8 D8 78 C7 45 ?? 75 07 50 E8 C7 45 ?? B1 D1 FF FF C7
         45 ?? 59 5D C3 8B C7 45 ?? FF 55 8B EC C7 45 ?? 83 EC 10 A1 66 C7 45
         ?? 33 35}
		$base_key_b_array = {3B C6 73 0F 8B 07 85 C0 74 02 FF D0 83 C7 04 3B FE
         72 F1 5F 5E C3 8B FF 56 B8 D8 78 75 07 50 E8 B1 D1 FF FF 59 5D C3 8B
         FF 55 8B EC 83 EC 10 A1 33 35 }

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and any of them
}
