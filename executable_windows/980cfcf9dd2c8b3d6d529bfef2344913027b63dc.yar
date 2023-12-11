import "pe"

rule IMPLANT_1_v1
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
		$STR1 = {6A ?? E8 ?? ?? FF FF 59 85 C0 74 0B 8B C8 E8 ?? ?? FF FF 8B F0
         EB 02 33 F6 8B CE E8 ?? ?? FF FF 85 F6 74 0E 8B CE E8 ?? ?? FF FF 56
         E8 ?? ?? FF FF 59}

	condition:
		( uint16(0)==0x5A4D) and all of them
}
