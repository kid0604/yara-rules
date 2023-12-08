import "pe"

rule IMPLANT_4_v8
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
		$f1 = {5E 81 EC 04 01 00 00 8B D4 68 04 01 00 00 52 6A 00 FF 57 1C 8B D4
         33 C9 03 D0 4A 41 3B C8 74 05 80 3A 5C 75 F5 42 81 EC 04 01 00 00 8B
         DC 52 51 53 68 04 01 00 00 FF 57 20 59 5A 66 C7 04 03 5C 20 56 57 8D
         3C 03 8B F2 F3 A4 C6 07 00 5F 5E 33 C0 50 68 80 00 00 00 6A 02 50 50
         68 00 00 00 40 53 FF 57 14 53 8B 4F 4C 8B D6 33 DB 30 1A 42 43 3B D9
         7C F8 5B 83 EC 04 8B D4 50 6A 00 52 FF 77 4C 8B D6 52 50 FF 57 24 FF
         57 18}
		$f2 = {5E 83 EC 1C 8B 45 08 8B 4D 08 03 48 3C 89 4D E4 89 75 EC 8B 45 08
         2B 45 10 89 45 E8 33 C0 89 45 F4 8B 55 0C 3B 55 F4 0F 86 98 00 00 00
         8B 45 EC 8B 4D F4 03 48 04 89 4D F4 8B 55 EC 8B 42 04 83 E8 08 D1 E8
         89 45 F8 8B 4D EC 83 C1 08 89 4D FC}
		$f3 = {5F 8B DF 83 C3 60 2B 5F 54 89 5C 24 20 8B 44 24 24 25 00 00 FF FF
         66 8B 18 66 81 FB 4D 5A 74 07 2D 00 00 01 00 EB EF 8B 48 3C 03 C8 66
         8B 19 66 81 FB 50 45 75 E0 8B E8 8B F7 83 EC 60 8B FC B9 60 00 00 00
         F3 A4 83 EF 60 6A 0D 59 E8 88 00 00 00 E2 F9 68 6C 33 32 00 68 73 68
         65 6C 54 FF 57}
		$a1 = {83 EC 04 60 E9 1E 01 00 00}

	condition:
		$a1 at pe.entry_point or any of ($f*)
}
