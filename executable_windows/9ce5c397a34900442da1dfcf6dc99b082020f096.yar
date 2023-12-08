import "pe"

rule IMPLANT_6_v4
{
	meta:
		description = "Sednit / EVILTOSS Implant by APT28"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		date = "2017-02-10"
		score = 85
		os = "windows"
		filetype = "executable"

	strings:
		$ASM = {53 5? 5? [6-15] ff d? 8b ?? b? a0 86 01 00 [7-13] ff d? ?b
         [6-10] c0 [0-1] c3}

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
