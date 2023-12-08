import "pe"

rule AHTeamEPProtector03faketElock061FEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Detects AHTeam EP Protector 03 fake tElock 061 FEUERRADER malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 [46] 90 FF E0 E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08 F3 EB FF E0 83 C0 28 50 E8 00 00 00 00 5E B3 33 8D 46 0E 8D 76 31 28 18 F8 73 00 C3 8B FE B9 3C 02 }

	condition:
		$a0 at pe.entry_point
}
