import "pe"

rule AHTeamEPProtector03fakeMicrosoftVisualC70FEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Detects AHTeam EP Protector 03 fake Microsoft Visual C 7.0 FEU ERRADER"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 [46] 90 FF E0 6A 00 68 [4] E8 [4] BF [4] 8B C7 E8 [4] 89 65 00 8B F4 89 3E 56 FF 15 [4] 8B 4E ?? 89 0D [3] 00 8B 46 00 A3 }

	condition:
		$a0 at pe.entry_point
}
