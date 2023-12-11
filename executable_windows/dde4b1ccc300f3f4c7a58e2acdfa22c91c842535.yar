import "pe"

rule AHTeamEPProtector03fakeASPack212FEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Detects AHTeam EP Protector 03 fake ASPack 2.12 FEUERRADER"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 [46] 90 FF E0 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB }

	condition:
		$a0 at pe.entry_point
}
