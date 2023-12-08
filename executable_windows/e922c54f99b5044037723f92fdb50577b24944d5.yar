import "pe"

rule AHTeamEPProtector03fakeASProtect10FEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Detects fake ASProtect 1.0 FE UERRADER protected files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 [46] 90 FF E0 60 E8 01 00 00 00 90 5D 81 ED 00 00 00 00 BB 00 00 00 00 03 DD 2B 9D }

	condition:
		$a0 at pe.entry_point
}
