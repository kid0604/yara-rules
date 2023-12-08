import "pe"

rule WARNINGTROJANHuiGeZi
{
	meta:
		author = "malware-lu"
		description = "Detects the WARNINGTROJANHuiGeZi trojan"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 81 C4 ?? FE FF FF 53 56 57 33 C0 89 85 ?? FE FF FF }

	condition:
		$a0 at pe.entry_point
}
