rule win_action_rat_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.action_rat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.action_rat"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { eb64 68???????? 8b4d0c 51 e8???????? }
		$sequence_1 = { 0f8596010000 8d4dc8 e8???????? 0fb6c0 85c0 752d }
		$sequence_2 = { 7409 c745e800000000 eb0c 8b4dfc ff15???????? 8945e8 }
		$sequence_3 = { e8???????? 8945f8 8b4dfc 51 8b4df8 e8???????? 8d4dd0 }
		$sequence_4 = { 8d8de4f7ffff e8???????? 50 e8???????? 83c414 8985d4f7ffff 83bdd4f7ffff00 }
		$sequence_5 = { 7527 c645af00 c645fc00 8d4db8 e8???????? c745fcffffffff 8d4d0c }
		$sequence_6 = { 8bf4 8965f0 8b4d08 51 e8???????? 83c404 50 }
		$sequence_7 = { 8b4d08 8b11 8b4d08 034a04 ff15???????? 83e801 83da00 }
		$sequence_8 = { 7209 c745d803000000 eb0b 8b4df8 83e901 d1e9 894dd8 }
		$sequence_9 = { 68c8000000 e8???????? 83c404 8945f0 c745fc00000000 837df000 7420 }

	condition:
		7 of them and filesize <480256
}
