import "pe"

rule AHTeamEPProtector03fakePCGuard403415FEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Detects AHTeam EP Protector 03 fake PC Guard 403415FEUERRADER malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 [46] 90 FF E0 FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 }

	condition:
		$a0 at pe.entry_point
}
