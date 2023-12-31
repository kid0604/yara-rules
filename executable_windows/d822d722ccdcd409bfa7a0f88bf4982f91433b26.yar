rule win_necurs_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.necurs."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.necurs"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 46 f7f6 8bc2 034508 5e 5d c3 }
		$sequence_1 = { 0f31 8bc8 a1???????? 56 8bf2 ba06e0a636 f7e2 }
		$sequence_2 = { eb12 e8???????? 2b7508 33d2 46 f7f6 8bc2 }
		$sequence_3 = { ba06e0a636 f7e2 03c8 a1???????? }
		$sequence_4 = { 13f2 33d2 030d???????? a3???????? a1???????? 13f2 }
		$sequence_5 = { 397508 7604 33c0 eb12 e8???????? }
		$sequence_6 = { 13f2 a3???????? 8935???????? 890d???????? 8bc1 5e c3 }
		$sequence_7 = { 03c8 a1???????? 13f2 33d2 }
		$sequence_8 = { 8d85ecfbffff 57 50 e8???????? 83c410 }
		$sequence_9 = { 33d7 33c1 52 50 e8???????? }
		$sequence_10 = { 8bc1 0bc7 7409 8bc1 8bd7 e9???????? }
		$sequence_11 = { 33c0 33d2 5e 5f c9 }
		$sequence_12 = { 8bd7 e9???????? 83caff 8bc2 }
		$sequence_13 = { 50 ffd6 8bf8 59 59 }
		$sequence_14 = { 53 ff15???????? 59 33c0 5e }
		$sequence_15 = { 57 57 57 8d8574ffffff 50 }

	condition:
		7 of them and filesize <475136
}
