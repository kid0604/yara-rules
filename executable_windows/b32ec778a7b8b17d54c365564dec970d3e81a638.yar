rule win_tinynuke_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.tinynuke."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tinynuke"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c3 55 8bec 817d0c00040000 }
		$sequence_1 = { 8d8530f6ffff 50 6802020000 ff15???????? 85c0 }
		$sequence_2 = { 57 8b7d10 57 ff15???????? 8bc8 33d2 }
		$sequence_3 = { ff15???????? 6a07 59 ff35???????? 33c0 }
		$sequence_4 = { 7508 ff35???????? eb06 ff35???????? 50 ff15???????? }
		$sequence_5 = { 53 8bf0 8d45fc 50 ff750c 57 }
		$sequence_6 = { 8945f4 8d85d4feffff 50 ff15???????? }
		$sequence_7 = { ff15???????? ff35???????? a3???????? ff75f8 ff15???????? ff35???????? a3???????? }
		$sequence_8 = { 50 ff15???????? ff35???????? 8d85a4feffff }
		$sequence_9 = { ff75ec ff75fc e8???????? 83c40c 5f }
		$sequence_10 = { ff35???????? 8d85a4feffff 50 ff15???????? }
		$sequence_11 = { ff15???????? a3???????? ff35???????? ff75f8 ff15???????? }
		$sequence_12 = { a3???????? 68e2010000 68???????? 68???????? e8???????? }
		$sequence_13 = { 8a00 3c0a 7409 3c0d 740f }
		$sequence_14 = { ff35???????? ff7508 ff15???????? 68???????? }
		$sequence_15 = { 6a2a 50 8945fc ff15???????? }
		$sequence_16 = { a3???????? ff35???????? ff75ec ff15???????? }
		$sequence_17 = { e8???????? eb18 83f803 7519 ff7608 }
		$sequence_18 = { ff7508 ff15???????? ff35???????? ff7508 }
		$sequence_19 = { ff15???????? 8b35???????? 8d430c 50 }
		$sequence_20 = { 75a4 8b7c241c 8b4728 891c24 }
		$sequence_21 = { 89442404 e8???????? 83ec08 e8???????? 3b44242c 740c 83c438 }
		$sequence_22 = { 89442404 e8???????? 8945fc 8b0f }
		$sequence_23 = { e8???????? 83ec08 891c24 c744241881000000 c744241400000000 c744241000000000 }
		$sequence_24 = { c7410800000000 895908 833e00 7504 890e }
		$sequence_25 = { 85c0 74e5 891c24 c744240400000000 e8???????? 83ec08 }
		$sequence_26 = { 8b0f 85c9 742a 8d440b02 85c9 }
		$sequence_27 = { ff7510 ff750c 56 750f ff75ec }
		$sequence_28 = { 89442408 e8???????? 0fb76f06 31ff }
		$sequence_29 = { 01de 8b16 85d2 7449 8b4604 }
		$sequence_30 = { 8bf0 85f6 7509 33c0 5f }

	condition:
		7 of them and filesize <1196032
}
