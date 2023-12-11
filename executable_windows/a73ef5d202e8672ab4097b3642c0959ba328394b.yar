import "pe"

rule AHTeamEPProtector03fakePEtite22FEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Detects fake PEtite 2.2 FE UERRADER used by AHTeam EP Protector 03"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 [46] 90 FF E0 B8 00 00 00 00 68 00 00 00 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 }

	condition:
		$a0 at pe.entry_point
}
