import "pe"

rule AHTeamEPProtector03fakePELockNT204FEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Detects AHTeam EP Protector 03 fake PE Lock NT 204 FEUERRADER"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 [46] 90 FF E0 EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 EB 03 CD 20 EB EB 01 EB }

	condition:
		$a0 at pe.entry_point
}
