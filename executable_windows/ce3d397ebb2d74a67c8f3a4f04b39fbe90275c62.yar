rule win_poscardstealer_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.poscardstealer."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.poscardstealer"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 897914 895910 56 c645fc03 8819 e8???????? }
		$sequence_1 = { 8bb00c594200 89450c 8d872b010000 99 8d5fff }
		$sequence_2 = { 7302 8bc1 50 8d4da0 e8???????? 8b7da4 8b75a0 }
		$sequence_3 = { b801000000 c746140f000000 897e10 8945fc c60600 837d2010 8b5d0c }
		$sequence_4 = { 83c704 89bd80edffff eb68 8b8d84edffff 3bd1 7549 8bc2 }
		$sequence_5 = { 837d1c10 c745e80f000000 c745e400000000 c645d400 720c 8b4d08 51 }
		$sequence_6 = { 6a00 50 e8???????? 8d4d8c c745fcffffffff }
		$sequence_7 = { 40 50 8d8d64ffffff 51 8d4dd4 }
		$sequence_8 = { 8d4b01 837d9410 8b4580 7303 }
		$sequence_9 = { 57 50 8d45f4 64a300000000 8b4518 898574ffffff 8b4508 }

	condition:
		7 of them and filesize <362496
}