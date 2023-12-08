rule APT_LNX_Academic_Camp_May20_Eraser_1
{
	meta:
		description = "Detects malware used in attack on academic data centers"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://csirt.egi.eu/academic-data-centers-abused-for-crypto-currency-mining/"
		date = "2020-05-16"
		hash1 = "552245645cc49087dfbc827d069fa678626b946f4b71cb35fa4a49becd971363"
		os = "linux"
		filetype = "executable"

	strings:
		$sc2 = { E6 FF FF 48 89 45 D0 8B 45 E0 BA 00 00 00 00 BE
               00 00 00 00 89 C7 E8 }
		$sc3 = { E6 FF FF 89 45 DC 8B 45 DC 83 C0 01 48 98 BE 01
               00 00 00 48 89 C7 E8 }

	condition:
		uint16(0)==0x457f and filesize <60KB and all of them
}
