import "pe"

rule IMPLANT_7_v1
{
	meta:
		description = "Implant 7 by APT29"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		date = "2017-02-10"
		score = 85
		os = "windows"
		filetype = "executable"

	strings:
		$STR1 = { 8A 44 0A 03 32 C3 0F B6 C0 66 89 04 4E 41 3B CF 72 EE }
		$STR2 = { F3 0F 6F 04 08 66 0F EF C1 F3 0F 7F 04 11 83 C1 10 3B CF 72 EB }

	condition:
		( uint16(0)==0x5A4D) and ($STR1 or $STR2)
}
