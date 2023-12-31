rule win_hyperssl_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.hyperssl."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hyperssl"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 75f2 5f 5e e9???????? c3 55 }
		$sequence_1 = { 0101 014514 2bf3 8b5d0c }
		$sequence_2 = { 8b413c 03c1 742a 8b4028 }
		$sequence_3 = { 33c2 897d88 33bd78ffffff 89458c 897594 8d7594 }
		$sequence_4 = { 40 5d c20c00 6a08 68???????? e8???????? 8b450c }
		$sequence_5 = { 0101 0100 0100 0100 }
		$sequence_6 = { 0100 0200 0200 0002 0002 }
		$sequence_7 = { 0105???????? 8d8d5cffffff 89855cffffff 898560ffffff }
		$sequence_8 = { 0108 3908 1bc9 f7d9 }
		$sequence_9 = { 2bc8 2bf0 5f 8a10 301401 8a10 }
		$sequence_10 = { 8b4028 03c1 7423 56 57 }
		$sequence_11 = { ff15???????? 8bc8 85c9 7436 8b413c }
		$sequence_12 = { 301401 8a10 301406 40 }
		$sequence_13 = { 0105???????? 8d558c 89458c 894590 }
		$sequence_14 = { 0108 3310 c1c607 c1c210 }
		$sequence_15 = { 301406 40 4f 75f2 5f }
		$sequence_16 = { 017e0c 8d4d08 e8???????? 5f }
		$sequence_17 = { 01442428 8b442428 884500 45 }
		$sequence_18 = { 017e0c 5f 8bc6 5e c20800 }
		$sequence_19 = { 016b08 897b04 5f 5e }
		$sequence_20 = { 017e0c 395e10 740f ff7610 }
		$sequence_21 = { 017e08 8bc3 e8???????? c20400 }
		$sequence_22 = { 017e08 50 e8???????? ff0d???????? }
		$sequence_23 = { 011d???????? 5f 8935???????? 5e }

	condition:
		7 of them and filesize <835584
}
