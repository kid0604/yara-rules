rule win_htprat_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.htprat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.htprat"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 741c 83f95c 7410 83f962 0f85ca000000 }
		$sequence_1 = { 33c0 3b5dfc 0f95c0 5f }
		$sequence_2 = { 895de8 c746140f000000 895e10 881e 33ff 895dfc c745e801000000 }
		$sequence_3 = { 8b45f0 8b4028 85c0 7406 50 e8???????? }
		$sequence_4 = { 64a100000000 50 b82c110000 e8???????? a1???????? 33c5 8945f0 }
		$sequence_5 = { 39b550efffff 740c ffb550efffff ff15???????? 39b554efffff }
		$sequence_6 = { 8b00 8d8d38efffff 51 8d8d08efffff 51 50 ff33 }
		$sequence_7 = { ffd6 898564efffff 3bc7 7e6d 8b8564efffff 33c9 }
		$sequence_8 = { ffd7 85c0 74e8 56 }
		$sequence_9 = { 6a78 b8???????? e8???????? 83658000 89bd7cffffff 33db }

	condition:
		7 of them and filesize <278528
}
