import "pe"

rule AHTeamEPProtector03fakeXtremeProtector105FEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Detects AHTeam EP Protector 03 fake Xtreme Protector 1.05 FEUERRADER"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 [46] 90 FF E0 E8 00 00 00 00 5D 81 00 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 }

	condition:
		$a0 at pe.entry_point
}
