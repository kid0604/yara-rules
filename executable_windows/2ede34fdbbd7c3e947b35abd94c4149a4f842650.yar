rule win_deadwood_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.deadwood."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.deadwood"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 2bc1 46 c1f803 83c404 3bc6 77d1 8b35???????? }
		$sequence_1 = { 8b75bc 56 e8???????? 83c404 8bc7 8b4df4 64890d00000000 }
		$sequence_2 = { e8???????? 8b5514 8b4b04 83c410 52 50 51 }
		$sequence_3 = { 83c404 c645fc31 e8???????? 83c438 8d4d90 e8???????? 8d8da4feffff }
		$sequence_4 = { 884dd4 c745fc01000000 84c9 0f84e4000000 8b4804 8d55e8 52 }
		$sequence_5 = { 8d55e4 52 03cb e8???????? 50 c645fc03 e8???????? }
		$sequence_6 = { 50 8d45f4 64a300000000 33db 895dfc 8bf7 897dcc }
		$sequence_7 = { 747e 8b5514 3d00010000 8b4510 7422 8b4d1c 57 }
		$sequence_8 = { 83c60c e9???????? 8b4de8 e9???????? 8b542408 8d420c 8b4ae4 }
		$sequence_9 = { e8???????? 50 8bcf 895dfc e8???????? 837de810 720c }

	condition:
		7 of them and filesize <1055744
}
