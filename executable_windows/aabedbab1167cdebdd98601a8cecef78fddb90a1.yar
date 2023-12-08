import "pe"

rule IMPLANT_2_v7
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
		$s1 = {10 A0 FA FD 83 3D 28 D4 1F FF 77 5? ?8 B4 50 CC 1E B0 78 D7 90 13
         21 C0 23 3D 28 BC 78 95 DE 4B B0 60 00 00 0F 7F 38 B4 50 C8 D5 9F E0
         25 DF F3 21 C0 28 BC 13 3D 2B 90 60 00 00 0F 7F 18 B4 50 C8 BC F2 21
         C0 28 B4 5E 48 B5 5E 00 8D 41 FE 83 F8 06 8B 45 ?? 72 ?? 8B 4D ?? 8B }
		$s2 = {28 D9 B0 00 00 00 00 FB 65 C0 AF E8 D3 40 28 B4 5? ?0 3C 20 FA FD
         88 D7 A0 18 D4 2F F3 3D 2F 77 5? ?C 1E B0 78 BC 73 21 C0 A3 3D 2B 90
         60 00 00 0F 7F 18 A4 D? ?8 B4 50 C8 0E 90 20 24 D? ?3 20 C0 28 B4 5?
         ?3 3D 2F 77 5? ?8 B4 50 C2 20 C0 28 BD 70 2D 93 01 E8 B4 D0 C8 D4 2F
         E3 B4 5E 88 B4 5? ?8 95 5? ?7 2A 05 F5 E5 B8 BE 55 DC 20 80 }

	condition:
		( uint16(0)==0x5A4D) and any of them
}
