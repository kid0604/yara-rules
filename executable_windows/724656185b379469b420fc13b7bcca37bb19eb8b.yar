rule win_erbium_stealer_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.erbium_stealer."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.erbium_stealer"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b55f4 52 ff15???????? 898578ffffff 8b450c 0fb708 }
		$sequence_1 = { e9???????? b808000000 6bc809 8b55f4 837c0a6400 7448 b808000000 }
		$sequence_2 = { 6a04 ff7508 8d4df8 ff75e4 ff75e0 6a00 }
		$sequence_3 = { 8d8424a0000000 7409 83c002 66833800 }
		$sequence_4 = { 6a00 6800100000 68???????? 8b45e8 }
		$sequence_5 = { ff15???????? eb08 33c0 eb04 8b442414 33ff 33db }
		$sequence_6 = { 8b11 81e200000080 741a 8b45f0 8b08 81e1ffff0000 }
		$sequence_7 = { 8955f8 b808000000 6bc805 8b55f4 }
		$sequence_8 = { 897dfc 3bf8 7455 0fb74f2c }
		$sequence_9 = { 83c102 51 8b55d0 52 ff55cc 8b4de8 8901 }

	condition:
		7 of them and filesize <33792
}
