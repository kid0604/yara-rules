import "pe"

rule win_conti_auto_alt_1
{
	meta:
		description = "Detect the risk of Ransomware Conti Rule 2"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 85c0 750f c705????????0b000000 e9???????? }
		$sequence_1 = { 0fb6c0 2bc8 8d04c9 c1e002 }
		$sequence_2 = { 03c1 03c0 99 f7fb 8d427f }
		$sequence_3 = { 753f 53 bb0c000000 57 }
		$sequence_4 = { 753f 53 bb0a000000 57 8d7e01 8d7375 }
		$sequence_5 = { 803900 7533 53 56 57 }
		$sequence_6 = { 56 8bf1 8975fc 803e00 }
		$sequence_7 = { 99 f7fb 8856ff 83ef01 75df }
		$sequence_8 = { 57 6a04 6800300000 6820005000 }
		$sequence_9 = { 6a01 6810660000 ff7508 ff15???????? }
		$sequence_10 = { 6800100000 68???????? ff75f8 ff15???????? 85c0 7508 6a01 }
		$sequence_11 = { 6aff ff75f0 ff15???????? ff75f4 ff15???????? }
		$sequence_12 = { 85c0 750f c705????????0a000000 e9???????? }
		$sequence_13 = { ff75fc ff15???????? e9???????? 6800800000 6a00 }
		$sequence_14 = { 8bce e8???????? 8bb6007d0000 85f6 75ef 6aff 6a01 }
		$sequence_15 = { 7605 b800005000 6a00 8d4c2418 51 50 ff742424 }
		$sequence_16 = { 7411 a801 740d 83f001 }
		$sequence_17 = { 85c0 ba0d000000 0f44ca 890d???????? }
		$sequence_18 = { 83c10b f7e9 c1fa02 8bc2 }
		$sequence_19 = { 83c00b 99 83c117 f7f9 }
		$sequence_20 = { ffd0 8b0d???????? 85c0 ba0d000000 }
		$sequence_21 = { ffd0 85c0 750f c705????????0c000000 }
		$sequence_22 = { 83c10b f7e9 03d1 c1fa06 8bc2 c1e81f }

	condition:
		7 of them and filesize <520192
}
