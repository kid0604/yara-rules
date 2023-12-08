import "pe"

rule AHTeamEPProtector03fakeSVKP13xFEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Detects AHTeam EP Protector 03 fake SVKP13 xFEUERRADER"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 [46] 90 FF E0 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 00 00 00 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 }

	condition:
		$a0 at pe.entry_point
}
