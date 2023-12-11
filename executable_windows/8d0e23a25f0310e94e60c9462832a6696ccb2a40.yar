import "pe"

rule APT28_SkinnyBoy_Implanter : RUSSIA
{
	meta:
		description = "Detects APT28 SkinnyBoy implanter"
		author = "Cluster25"
		date = "2021-05-24"
		reference = "https://cluster25.io/wp-content/uploads/2021/05/2021-05_FancyBear.pdf"
		hash1 = "ae0bc3358fef0ca2a103e694aa556f55a3fed4e98ba57d16f5ae7ad4ad583698"
		os = "windows"
		filetype = "executable"

	strings:
		$enc_string = {F3 0F 7E 05 ?? ?? ?? ?? 6? [5] 6A ?? 66 [6] 66 [7] F3 0F 7E 05 ?? ?? ?? ?? 8D
      85 [4] 6A ?? 50 66 [7] E8}
		$heap_ops = {8B [1-5] 03 ?? 5? 5? 6A 08 FF [1-6] FF ?? ?? ?? ?? ?? [0-6] 8B ?? [0-6] 8?}
		$xor_cycle = { 8A 8C ?? ?? ?? ?? ?? 30 8C ?? ?? ?? ?? ?? 42 3B D0 72 }

	condition:
		uint16(0)==0x5a4d and pe.is_dll() and filesize <100KB and $xor_cycle and $heap_ops and $enc_string
}
