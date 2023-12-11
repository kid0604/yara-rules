import "pe"

rule VIRUSIWormKLEZ
{
	meta:
		author = "malware-lu"
		description = "Detects the VIRUSIWormKLEZ malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 40 D2 40 ?? 68 04 AC 40 ?? 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 BC D0 }

	condition:
		$a0
}
