import "pe"

rule IMPLANT_4_v2
{
	meta:
		description = "BlackEnergy / Voodoo Bear Implant by APT28"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		date = "2017-02-10"
		score = 85
		os = "windows"
		filetype = "executable"

	strings:
		$BUILD_USER32 = {75 73 65 72 ?? ?? ?? 33 32 2E 64}
		$BUILD_ADVAPI32 = {61 64 76 61 ?? ?? ?? 70 69 33 32}
		$CONSTANT = {26 80 AC C8}

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and all of them
}
