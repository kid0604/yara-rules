import "pe"

rule IMPLANT_2_v8
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
		$STR1 = {8B ?? 44 89 44 24 60 41 F7 E0 8B F2 B8 AB AA AA AA C1 EE 02 89
         74 24 58 44 8B ?? 41 F7 ?? 8B CA BA 03 00 00 00 C1 E9 02 89 0C 24 8D
         04 49 03 C0 44 2B ?? 44 89 ?? 24 04 3B F1 0F 83 ?? 01 00 00 8D 1C 76
         4C 89 6C 24 }
		$STR2 = {C5 41 F7 E0 ?? ?? ?? ?? ?? ?? 8D 0C 52 03 C9 2B C1 8B C8 ?? 8D
         04 ?? 46 0F B6 0C ?? 40 02 C7 41 8D 48 FF 44 32 C8 B8 AB AA AA AA F7
         E1 C1 EA 02 8D 04 52 03 C0 2B C8 B8 AB AA AA AA 46 22 0C ?? 41 8D 48
         FE F7 E1 C1 EA 02 8D 04 52 03 C0 2B C8 8B C1 }
		$STR3 = {41 F7 E0 C1 EA 02 41 8B C0 8D 0C 52 03 C9 2B C1 8B C8 42 8D 04
         1B 46 0F B6 0C ?? 40 02 C6 41 8D 48 FF 44 32 C8 B8 AB AA AA AA F7 E1
         C1 EA 02 8D 04 52 03 C0 2B C8 B8 AB AA AA AA }
		$STR4 = {46 22 0C ?? 41 8D 48 FE F7 E1 C1 EA 02 8D 04 52 8B 54 24 58 03
         C0 2B C8 8B C1 0F B6 4F FF 42 0F B6 04 ?? 41 0F AF CB C1 }

	condition:
		( uint16(0)==0x5A4D) and any of them
}
