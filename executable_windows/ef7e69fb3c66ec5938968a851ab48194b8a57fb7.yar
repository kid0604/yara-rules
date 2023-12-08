import "pe"

rule IMPLANT_2_v12
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
		$STR1 = {48 83 [2] 48 89 [3] c7 44 [6] 4c 8d 05 [3] 00 BA 01 00 00 00
         33 C9 ff 15 [2] 00 00 ff 15 [2] 00 00 3D B7 00 00 00 75 ?? 48 8D 15
         ?? 00 00 00 48 8B CC E8}

	condition:
		( uint16(0)==0x5A4D) and all of them
}
