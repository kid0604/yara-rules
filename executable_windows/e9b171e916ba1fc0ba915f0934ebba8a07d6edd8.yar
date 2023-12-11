rule win_red_gambler_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.red_gambler."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.red_gambler"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? ff15???????? 8d8df0fdffff 51 ffd6 }
		$sequence_1 = { 50 51 57 ffd3 85c0 7418 8b95f0feffff }
		$sequence_2 = { 33c0 8906 894604 8bc7 85ff 741d }
		$sequence_3 = { 50 e8???????? 61 8bf0 56 }
		$sequence_4 = { 85ff 7e59 8b5d08 8bf1 2bd9 897d0c 8bca }
		$sequence_5 = { 8955f5 ffd7 85c0 742b }
		$sequence_6 = { b9???????? 2bce 6a05 83e905 }
		$sequence_7 = { 8d4de8 51 6a40 ba???????? 2bd6 6a05 }
		$sequence_8 = { 6800010000 8d8d98fdffff 51 8d9598feffff 52 }
		$sequence_9 = { 51 ff15???????? 83c414 6a00 6a00 }
		$sequence_10 = { 4f 7bac 6617 5e }
		$sequence_11 = { 8d8598fdffff 50 68???????? 8d8d98fbffff 68???????? 51 ff15???????? }
		$sequence_12 = { 3e3e25162f062d 2b2a bee7eee947 7c26 }
		$sequence_13 = { 6a00 8d9598fbffff 52 68???????? 6a00 6a00 ff15???????? }
		$sequence_14 = { 6800010000 8d85fcfeffff 50 6a00 ff15???????? }
		$sequence_15 = { 07 642827 3ccf 7bce }
		$sequence_16 = { 004f21 7ea2 bba7bc3d96 21903e461ca7 bb7a77149f }
		$sequence_17 = { 6a8c 44 e247 9a74b12a7c274e 627627 4f }
		$sequence_18 = { 48 44 40 6c }
		$sequence_19 = { 842a 06 7f6f c8603a0c 7364 }
		$sequence_20 = { 8d8594fbffff 50 8d4d98 51 }
		$sequence_21 = { 8d4d98 51 ff15???????? 8d5598 52 8d8598fdffff 50 }
		$sequence_22 = { 8d9598feffff 52 ff15???????? 8d8594fbffff }
		$sequence_23 = { 6800010000 8d8dfcfdffff 51 6a00 }
		$sequence_24 = { 07 93 60 58 0e 4c }
		$sequence_25 = { e8???????? 68???????? ff15???????? 8b7508 c7465c486b4000 83660800 33ff }
		$sequence_26 = { ff15???????? 6a5c 8d8dfcfeffff 51 }
		$sequence_27 = { ff15???????? 8bf0 85f6 0f8492000000 8b1d???????? 68???????? }
		$sequence_28 = { 56 e8???????? 8d0445648e4000 8bc8 }
		$sequence_29 = { 68???????? 50 ff15???????? 8d8dfcfeffff 51 ff15???????? 8bf0 }
		$sequence_30 = { 8b3d???????? 6aff ffd7 ffd3 56 ff15???????? 6888130000 }
		$sequence_31 = { 40 0080444000a4 44 40 }

	condition:
		7 of them and filesize <327680
}
