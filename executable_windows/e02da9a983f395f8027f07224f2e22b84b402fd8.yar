import "pe"

rule UnderGroundCrypterbyBooster2000
{
	meta:
		author = "malware-lu"
		description = "Detects the Underground Crypter by Booster2000"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 74 3C 00 11 E8 94 F9 FF FF E8 BF FE FF FF E8 0A F3 FF FF 8B C0 }

	condition:
		$a0
}
