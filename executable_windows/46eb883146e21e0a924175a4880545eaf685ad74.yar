import "pe"

rule AHTeamEPProtector03fakekkryptor9kryptoraFEUERRADER
{
	meta:
		author = "malware-lu"
		description = "Detects AHTeamEPProtector03fakekkryptor9kryptoraFEUERRADER malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 [46] 90 FF E0 60 E8 [4] 5E B9 00 00 00 00 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9 }

	condition:
		$a0 at pe.entry_point
}
