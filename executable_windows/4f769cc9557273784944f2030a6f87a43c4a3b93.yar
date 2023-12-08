import "pe"

rule IMPLANT_1_v7
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
		$XOR_FUNCT = { C7 45 ?? ?? ?? 00 10 8B 0E 6A ?? FF 75 ?? E8 ?? ?? FF FF }

	condition:
		( uint16(0)==0x5A4D) and all of them
}
