import "pe"

rule IMPLANT_2_v4
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
		$STR1 = {55 8b ec 6a fe 68 [4] 68 [4] 64 A1 00 00 00 00 50 83 EC 0C 53
         56 57 A1 [4] 31 45 F8 33 C5 50 8D 45 F0 64 A3 00 00 00 00 [8-14] 68
         [4] 6a 01 [1-2] FF 15 [4] FF 15 [4] 3D B7 00 00 00 75 27}

	condition:
		( uint16(0)==0x5A4D) and all of them
}
