rule win_liteduke_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.liteduke."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.liteduke"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff7514 ff7510 ff750c ff7508 e8???????? 50 09c0 }
		$sequence_1 = { 6a03 68000000c0 68???????? ff15???????? 40 0f84e0000000 48 }
		$sequence_2 = { 66a5 b85c0a0000 66ab fe45f4 41 83f91a }
		$sequence_3 = { 7c56 8b55f8 8d441318 ff75fc }
		$sequence_4 = { 3c5a 7602 0406 aa 4d e0e0 75d1 }
		$sequence_5 = { a3???????? 6a04 6800300000 6a08 6a00 ff15???????? }
		$sequence_6 = { 8d85e0fdffff ff7508 50 ff15???????? 50 ff7508 ff15???????? }
		$sequence_7 = { ff15???????? ff75fc ff15???????? 833d????????01 740d 833d????????01 }
		$sequence_8 = { 8b4e38 83c624 bf???????? 31db 8b06 88c3 }
		$sequence_9 = { 09c0 0f8405020000 8945d8 6800010000 6a00 ff15???????? 09c0 }

	condition:
		7 of them and filesize <1171456
}
