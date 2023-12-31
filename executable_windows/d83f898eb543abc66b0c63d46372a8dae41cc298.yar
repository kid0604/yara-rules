rule win_ccleaner_backdoor_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.ccleaner_backdoor."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ccleaner_backdoor"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 750a b857000780 e9???????? e8???????? }
		$sequence_1 = { 57 ffd6 50 ff15???????? 8b3d???????? 59 }
		$sequence_2 = { 03c0 894340 8b7340 418bc4 }
		$sequence_3 = { 03c6 85c0 7f09 488b0a 488b01 ff5008 488b4b28 }
		$sequence_4 = { 48 8bc6 49 8d4802 48 2bc2 48 }
		$sequence_5 = { 01442424 eb30 8b4508 897518 }
		$sequence_6 = { 01442418 03c8 8954242c 8b542470 }
		$sequence_7 = { 013d???????? 8b04b5d8970210 0500080000 3bc8 }
		$sequence_8 = { c1ee02 2bfe 4f 41 3b7d10 7215 }
		$sequence_9 = { 01461c 8b542424 85d2 7405 }
		$sequence_10 = { 6a02 57 6a03 8d85f0feffff 68000000c0 50 }
		$sequence_11 = { 01cc cc 48895c2408 57 }
		$sequence_12 = { 00cc cc 4057 4883ec50 4533db }
		$sequence_13 = { 8b4508 2bc1 83f801 720e 803900 7510 81c6ff000000 }
		$sequence_14 = { 013e 33c0 8b16 83c410 }
		$sequence_15 = { 85ff 7509 56 ff15???????? eb1a 8d4608 6894910000 }
		$sequence_16 = { 83e800 746e 48 742d 48 0f85bb000000 8a06 }
		$sequence_17 = { 8d45ac 6a0c 50 c745ac057d9b78 }
		$sequence_18 = { 85c0 0f84a6000000 8b45fc 397df8 }
		$sequence_19 = { 2bf8 41 41 3bfa 7523 2b5510 8b4514 }
		$sequence_20 = { 01460c 488b3f 493bfc 0f8554ffffff }
		$sequence_21 = { 50 8d85d0feffff 50 53 897dfc ff15???????? 8d85d0feffff }
		$sequence_22 = { 8bf3 8db888000000 85f6 7420 }
		$sequence_23 = { 00cc cc 4883ec28 488b11 }
		$sequence_24 = { 01442454 03d1 294c2450 8b4c2410 }
		$sequence_25 = { 03c6 4863d0 4c8d0c12 4c8d4718 }
		$sequence_26 = { e8???????? eb0d 69c0e8030000 50 ff15???????? 5e c9 }
		$sequence_27 = { e9???????? 49 8b02 49 83c208 48 8902 }
		$sequence_28 = { 012e 33c0 5f 5e 5d }
		$sequence_29 = { 740a 833900 7405 833a00 7504 33c0 c9 }

	condition:
		7 of them and filesize <377856
}
