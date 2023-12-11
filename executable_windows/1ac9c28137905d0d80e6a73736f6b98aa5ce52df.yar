import "pe"

rule Upackv037v038BetaStripbaserelocationtableOptionDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Upack v0.37/v0.38 Beta with the Strip base relocation table option"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 }

	condition:
		$a0
}
