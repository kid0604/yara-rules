import "pe"

rule IMPLANT_2_v1
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
		$STR1 = { 8d ?? fa [2] e8 [2] FF FF C7 [2-5] 00 00 00 00 8D [2-5] 5? 6a 00 6a 01}

	condition:
		( uint16(0)==0x5A4D) and all of them
}
