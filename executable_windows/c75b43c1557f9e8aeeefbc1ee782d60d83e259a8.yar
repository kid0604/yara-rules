rule win_regretlocker_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.regretlocker."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.regretlocker"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 50 8d8524ffffff 50 e8???????? f20f10450c 83c418 f20f5e4514 }
		$sequence_1 = { 83d600 6a18 58 03d8 3b5de0 75d6 0facf714 }
		$sequence_2 = { 8d4f18 e8???????? 84c0 753e 56 8bcf e8???????? }
		$sequence_3 = { 46 e8???????? 59 3bf0 0f86b8feffff e9???????? e8???????? }
		$sequence_4 = { c645fc05 e8???????? 33c9 884dcc ff75cc 894d8c 894d90 }
		$sequence_5 = { 8b4508 8b550c 8910 894804 5d c20800 56 }
		$sequence_6 = { 8bec 8b4108 2b01 6a6c 59 99 f7f9 }
		$sequence_7 = { 56 56 e8???????? 83c40c 8bc6 5e 5d }
		$sequence_8 = { 8b04c5046e4500 5d c3 8bff 55 8bec 56 }
		$sequence_9 = { 3b75e0 75a9 8d8520ffffff 50 e8???????? 59 8bb520ffffff }

	condition:
		7 of them and filesize <1021952
}
