import "pe"

rule IMPLANT_1_v5
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
		$drivername = { 6A 30 ?? 6A 33 [5] 6A 37 [5] 6A 32 [5] 6A 31 [5] 6A 77
         [5] 6A 69 [5] 6A 6E [5] 6A 2E [5] 6A 73 [5-9] 6A 79 [5] 6A 73 }
		$mutexname = { C7 45 ?? 2F 2F 64 66 C7 45 ?? 63 30 31 65 C7 45 ?? 6C 6C
         36 7A C7 45 ?? 73 71 33 2D C7 45 ?? 75 66 68 68 66 C7 45 ?? 66 }

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and any of them
}
