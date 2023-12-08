import "pe"

rule SimbiOZPolyCryptorvxxExtranger
{
	meta:
		author = "malware-lu"
		description = "Detects SimbiOZPolyCryptorvxxExtranger malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 60 E8 00 00 00 00 5D 81 ED [4] 8D 85 [4] 68 [4] 50 E8 }

	condition:
		$a0 at pe.entry_point
}
