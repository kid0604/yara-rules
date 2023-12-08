import "pe"

rule AHTeamEPProtector03fakeVIRUSIWormHybrisFEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Detects AHTeam EP Protector 03 fake virus IWorm.Hybris.F EUERRADER"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 [46] 90 FF E0 EB 16 A8 54 00 00 47 41 42 4C 4B 43 47 43 00 00 00 00 00 00 52 49 53 00 FC 68 4C 70 40 00 FF 15 }

	condition:
		$a0 at pe.entry_point
}
