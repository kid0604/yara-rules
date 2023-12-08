rule Makop_Ransomware_2
{
	meta:
		description = "Detect the risk of Ransomware Makop Rule 5"
		hash1 = "082a2ce2dde8b3a50f2d499496879e85562ee949cb151c8052eaaa713cddd0f8"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "CryptSetKeyParam" fullword ascii
		$s2 = "CryptImportKey" fullword ascii
		$opcode1 = {8B 44 24 08 8B 0E 57 6A 00 6A 00 6A 2C 50 51 FF 15 [4] 85 C0 75 0C}
		$opcode2 = {6A 00 52 6A 01 50 FF 15 [4] 85 C0}

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
