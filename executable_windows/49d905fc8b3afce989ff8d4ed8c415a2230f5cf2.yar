rule win_havoc_ntdll_hashes_oct_2022
{
	meta:
		author = "embee_research @ HuntressLabs"
		vendor = "Huntress Research"
		date = "2022/10/11"
		description = "Detection of havoc demons via hardcoded ntdll api hashes"
		os = "windows"
		filetype = "executable"

	strings:
		$nt_hash1 = {53 17 e6 70}
		$nt_hash2 = {43 6a 45 9e}
		$nt_hash3 = {ec b8 83 f7}
		$nt_hash4 = {88 28 e9 50}
		$nt_hash5 = {f6 99 5a 2e}
		$nt_hash6 = {da 81 b3 c0}
		$nt_hash7 = {d7 71 ba 70}
		$nt_hash8 = {88 2b 49 8e}
		$nt_hash9 = {ef f0 a1 3a}
		$nt_hash10 = {f5 39 34 7c}
		$nt_hash11 = {70 f2 ab 35}
		$nt_hash12 = {1d aa a3 3c}
		$nt_hash13 = {11 b2 8f f7}
		$nt_hash14 = {4c 7c de a5}
		$nt_hash15 = {90 fe 61 95}
		$nt_hash16 = {d0 ee 33 77}
		$nt_hash17 = {a9 af 4b 55}
		$nt_hash18 = {0e 21 0c 88}
		$nt_hash19 = {3d 13 8e 8b}
		$nt_hash20 = {7d 74 58 ca}

	condition:
		(3 of them ) and ( uint16(0)==0x5a4d or uint16(0)==0x00e8 or uint16(0)==0x4856)
}
