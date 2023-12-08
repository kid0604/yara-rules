import "pe"

rule BeRoEXEPackerV100BeRo
{
	meta:
		author = "malware-lu"
		description = "Detects files packed with BeRoEXEPackerV100BeRo"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BA [4] 8D B2 [4] 8B 46 ?? 85 C0 74 51 03 C2 8B 7E ?? 8B 1E 85 DB 75 02 8B DF 03 DA 03 FA 52 57 50 FF 15 [4] 5F 5A 85 C0 74 2F 8B C8 8B 03 85 C0 74 22 0F BA F0 1F 72 04 8D 44 [2] 51 52 57 50 51 FF 15 [4] 5F 5A 59 85 C0 74 0B AB 83 C3 04 EB D8 83 C6 14 EB AA 61 C3 }

	condition:
		$a0
}
