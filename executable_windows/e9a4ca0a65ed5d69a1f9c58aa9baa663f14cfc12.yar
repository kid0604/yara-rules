import "pe"

rule AHTeamEPProtector03fakePECrypt102FEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Detects AHTeam EP Protector 03 fake PE Crypt 102 FEUERRADER"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 [46] 90 FF E0 E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 }

	condition:
		$a0 at pe.entry_point
}
