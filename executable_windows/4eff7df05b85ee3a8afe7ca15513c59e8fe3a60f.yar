import "pe"

rule AHTeamEPProtector03fakeSpalsher1x3xFEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Detects AHTeam EP Protector 03 fake splash screen"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 [46] 90 FF E0 9C 60 8B 44 24 24 E8 00 00 00 00 5D 81 ED 00 00 00 00 50 E8 ED 02 00 00 8C C0 0F 84 }

	condition:
		$a0 at pe.entry_point
}
