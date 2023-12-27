rule win_isr_stealer_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.isr_stealer."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.isr_stealer"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { fb b05e 2bc1 e8???????? 661e }
		$sequence_1 = { 08ac22c115978d 0e e8???????? 07 }
		$sequence_2 = { 1c8b 53 2456 2bd1 807e6543 }
		$sequence_3 = { 46 1e 301b 15c2c8c807 d6 12d8 }
		$sequence_4 = { 8d16 b205 07 d32cb6 08ac22c115978d 0e e8???????? }
		$sequence_5 = { a7 8d16 b205 07 d32cb6 08ac22c115978d }
		$sequence_6 = { 07 fb b05e 2bc1 e8???????? }
		$sequence_7 = { 8d16 b205 07 d32cb6 08ac22c115978d 0e }
		$sequence_8 = { 07 d32cb6 08ac22c115978d 0e e8???????? }
		$sequence_9 = { e8???????? 07 fb b05e 2bc1 e8???????? 661e }

	condition:
		7 of them and filesize <540672
}