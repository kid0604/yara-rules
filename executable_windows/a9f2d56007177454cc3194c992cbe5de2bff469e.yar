rule win_thunker_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.thunker."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.thunker"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 89c2 2b95ecfdffff d1ea 8995e8fdffff }
		$sequence_1 = { 5b 5d c3 55 89e5 81ecc8010000 }
		$sequence_2 = { 50 e8???????? 83c438 c645c134 }
		$sequence_3 = { 50 e8???????? 83c410 837dfc00 75c9 56 e8???????? }
		$sequence_4 = { 50 57 e8???????? 83a5e8edffff00 }
		$sequence_5 = { e8???????? e8???????? ff7510 ff750c ff7508 a1???????? }
		$sequence_6 = { 89c3 6a03 68???????? 57 e8???????? 83c40c 09c0 }
		$sequence_7 = { 8d85f0edffff 50 e8???????? 83c40c c685f1edffff07 }
		$sequence_8 = { 83c424 09c0 7417 68???????? }
		$sequence_9 = { ff750c 68???????? 57 e8???????? 8945fc }

	condition:
		7 of them and filesize <73728
}
