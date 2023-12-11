import "pe"

rule IMPLANT_2_v3
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
		$STR1 = {C1 EB 07 8D ?? 01 32 1C ?? 33 D2 }
		$STR2 = {2B ?? 83 ?? 06 0F 83 ?? 00 00 00 EB 02 33 }
		$STR3 = {89 ?? ?? 89 ?? ?? 89 55 ?? 89 45 ?? 3B ?? 0F 83 ?? 00 00 00 8D
         ?? ?? 8D ?? ?? FE }

	condition:
		( uint16(0)==0x5A4D) and any of them
}
