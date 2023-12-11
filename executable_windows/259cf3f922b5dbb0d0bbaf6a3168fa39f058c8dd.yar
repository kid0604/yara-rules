import "pe"

rule IMPLANT_4_v10
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
		$ = {A1B05C72}
		$ = {EB3D0384}
		$ = {6F45594E}
		$ = {71815A4E}
		$ = {D5B03E72}
		$ = {6B43594E}
		$ = {F572993D}
		$ = {665D9DC0}
		$ = {0BE7A75A}
		$ = {F37443C5}
		$ = {A2A474BB}
		$ = {97DEEC67}
		$ = {7E0CB078}
		$ = {9C9678BF}
		$ = {4A37A149}
		$ = {8667416B}
		$ = {0A375BA4}
		$ = {DC505A8D}
		$ = {02F1F808}
		$ = {2C819712}

	condition:
		uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550 and 15 of them
}
