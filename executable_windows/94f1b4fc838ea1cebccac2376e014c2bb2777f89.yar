import "pe"

rule BlackEnergyDDoSBotCrypter
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting BlackEnergy DDoS Bot Crypter"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 [2] 81 EC 1C 01 00 00 53 56 57 6A 04 BE 00 30 00 00 56 FF 35 00 20 11 13 6A 00 E8 ?? 03 00 00 [2] 83 C4 10 ?? FF 89 7D F4 0F }

	condition:
		$a0 at pe.entry_point
}
