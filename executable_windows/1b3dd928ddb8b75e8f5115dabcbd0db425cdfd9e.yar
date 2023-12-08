import "pe"

rule AHTeamEPProtector03fakeBorlandDelphi6070FEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Detects AHTeam EP Protector 03 fake Borland Delphi 6.0-7.0 FEUERRADER"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 [46] 90 FF E0 53 8B D8 33 C0 A3 00 00 00 00 6A 00 E8 00 00 00 FF A3 00 00 00 00 A1 00 00 00 00 A3 00 00 00 00 33 C0 A3 00 00 00 00 33 C0 A3 00 00 00 00 E8 }

	condition:
		$a0 at pe.entry_point
}
