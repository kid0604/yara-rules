import "pe"

rule AHTeamEPProtector03fakeStonesPEEncryptor20FEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting AHTeamEPProtector03fakeStonesPEEncryptor20FEUERRADER malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 [46] 90 FF E0 53 51 52 56 57 55 E8 00 00 00 00 5D 81 ED 42 30 40 00 FF 95 32 35 40 00 B8 37 30 40 00 03 C5 2B 85 1B 34 40 00 89 85 27 34 40 00 83 }

	condition:
		$a0 at pe.entry_point
}
