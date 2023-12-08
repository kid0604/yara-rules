import "pe"

rule IMPLANT_1_v2
{
	meta:
		description = "Downrage Implant by APT28"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		date = "2017-02-10"
		score = 85
		os = "windows"
		filetype = "executable"

	strings:
		$STR1 = {83 3E 00 53 74 4F 8B 46 04 85 C0 74 48 83 C0 02 50 E8 ?? ?? 00
         00 8B D8 59 85 DB 74 38 8B 4E 04 83 F9 FF 7E 21 57 }
		$STR2 = {55 8B EC 8B 45 08 3B 41 08 72 04 32 C0 EB 1B 8B 49 04 8B 04 81
         80 78 19 01 75 0D FF 70 10 FF [5] 85 C0 74 E3 }

	condition:
		( uint16(0)==0x5A4D) and any of them
}
