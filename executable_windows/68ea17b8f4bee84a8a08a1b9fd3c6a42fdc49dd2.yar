rule win_boaxxe_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.boaxxe."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.boaxxe"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 85db 7e17 8bc6 8bcf 8bd3 e8???????? 8bd6 }
		$sequence_1 = { ff75f0 8d45ec 8b55fc 8a543203 e8???????? ff75ec 8d45f4 }
		$sequence_2 = { 33c0 8945f4 8b55fc a1???????? e8???????? 85c0 0f8e8c000000 }
		$sequence_3 = { 8d8598fdffff 33c9 ba68020000 e8???????? 68???????? e8???????? }
		$sequence_4 = { 52 50 8d8518f1ffff e8???????? ffb518f1ffff 8d45f8 ba06000000 }
		$sequence_5 = { 8b45ec e8???????? 8b55c0 8d45ec e8???????? 6a00 8d45f4 }
		$sequence_6 = { 8d45f0 e8???????? 8d9570f7ffff 33c0 e8???????? 8b8578f7ffff 8b55f8 }
		$sequence_7 = { 56 57 8bfe 8db5a8f7ffff b910020000 f3a5 66a5 }
		$sequence_8 = { 8b45b4 33c9 8b55f4 e8???????? 8bd0 a1???????? }
		$sequence_9 = { 8d95f4fdffff b904010000 e8???????? 8b85c4fdffff 8d95c8fdffff e8???????? 8b85c8fdffff }

	condition:
		7 of them and filesize <1146880
}
