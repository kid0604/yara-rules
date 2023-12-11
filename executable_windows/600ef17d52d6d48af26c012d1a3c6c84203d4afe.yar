rule win_dorkbot_ngrbot_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.dorkbot_ngrbot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dorkbot_ngrbot"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 99 b91a000000 f7f9 5b 83c241 668917 0fb645fd }
		$sequence_1 = { 687e660480 50 e8???????? 46 83fe32 7cd4 }
		$sequence_2 = { e8???????? 83c414 83f801 0f84cd000000 8b55f8 8b45fc 8b0cb508643a02 }
		$sequence_3 = { 53 56 e8???????? 8b5508 50 52 e8???????? }
		$sequence_4 = { 50 68???????? 68???????? 68???????? e8???????? e8???????? 8b4cbe04 }
		$sequence_5 = { 8b7318 51 e8???????? 8b9704543a02 8902 8b8704543a02 83c404 }
		$sequence_6 = { 8d8dfcfbffff 68???????? 51 e8???????? 8b3d???????? 83c440 68???????? }
		$sequence_7 = { 51 833d????????00 53 8b5d0c 56 c745fc00000000 0f8456010000 }
		$sequence_8 = { 52 e8???????? 83c404 5f b801000000 5e }
		$sequence_9 = { 7514 8a55ff 80e207 80fa05 7509 83c004 eb04 }

	condition:
		7 of them and filesize <638976
}
