import "pe"

rule IMPLANT_2_v17
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
		$STR1 = { 24108b44241c894424148b4424246836 }
		$STR2 = { 518d4ddc516a018bd08b4de4e8360400 }
		$STR3 = { e48178061591df75740433f6eb1a8b48 }
		$STR4 = { 33d2f775f88b45d402d903c641321c3a }
		$STR5 = { 006a0056ffd083f8ff74646a008d45f8 }

	condition:
		( uint16(0)==0x5A4D) and 2 of them
}
