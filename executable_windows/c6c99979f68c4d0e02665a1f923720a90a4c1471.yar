import "pe"

rule IMPLANT_6_v3
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
		$deob_func = { 8D 46 01 02 D1 83 E0 07 8A 04 38 F6 EA 8B D6 83 E2 07 0A
         04 3A 33 D2 8A 54 37 FE 03 D3 03 D1 D3 EA 32 C2 8D 56 FF 83 E2 07 8A
         1C 3A 8A 14 2E 32 C3 32 D0 41 88 14 2E 46 83 FE 0A 7C ?? }

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
