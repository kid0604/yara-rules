import "pe"

rule AHTeamEPProtector03fakePESHiELD2xFEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Detects fake PE files protected by AHTeam EP Protector 03 and SHiELD 2.x FEUERRADER"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 [46] 90 FF E0 60 E8 00 00 00 00 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }

	condition:
		$a0 at pe.entry_point
}
