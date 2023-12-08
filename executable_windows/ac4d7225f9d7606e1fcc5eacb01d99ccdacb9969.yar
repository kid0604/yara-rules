import "pe"

rule IMPLANT_6_v6
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
		$Init1_fun = {68 10 27 00 00 FF 15 ?? ?? ?? ?? A1 ?? ?? ?? ?? 6A FF 50
         FF 15 ?? ?? ?? ?? 33 C0 C3}

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
