rule win_kagent_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.kagent."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kagent"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c1f803 85c0 7e29 33f6 85c0 }
		$sequence_1 = { 48 5d c3 8bff 55 8bec 83ec34 }
		$sequence_2 = { f3a5 8bc8 83e103 f3a4 8dbddcfeffff 4f }
		$sequence_3 = { 0bc8 51 e8???????? 898388000000 c6838c00000001 }
		$sequence_4 = { f7d9 0bc8 51 e8???????? 898380000000 c6838400000001 8b8380000000 }
		$sequence_5 = { 85f6 7405 e8???????? 57 e8???????? 8b75f0 83c404 }
		$sequence_6 = { 8b7de4 41 894dd0 83f904 0f8c78ffffff c745d000000000 8b75d0 }
		$sequence_7 = { 53 8975f0 e8???????? 8975fc 53 c703???????? }
		$sequence_8 = { 51 53 e8???????? 83c410 894604 8bc6 5f }
		$sequence_9 = { 741c b800000400 5f 5e 5b 8b8c24b8050000 }

	condition:
		7 of them and filesize <4972544
}
