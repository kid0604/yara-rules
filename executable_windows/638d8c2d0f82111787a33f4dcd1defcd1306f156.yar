import "pe"

rule AHTeamEPProtector03fakeVOBProtectCDFEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Detects AHTeam EP Protector 03 fake VOB Protect CDF EU ERRADER"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 [46] 90 FF E0 5F 81 EF 00 00 00 00 BE 00 00 40 00 8B 87 00 00 00 00 03 C6 57 56 8C A7 00 00 00 00 FF 10 89 87 00 00 00 00 5E 5F }

	condition:
		$a0 at pe.entry_point
}
