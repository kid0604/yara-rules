rule win_grateful_pos_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.grateful_pos."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.grateful_pos"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { eb07 b8fcffffff eb02 33c0 }
		$sequence_1 = { 7407 b8f6ffffff eb02 33c0 }
		$sequence_2 = { e8???????? 99 b980ee3600 f7f9 }
		$sequence_3 = { 7411 e8???????? e8???????? 33c0 e9???????? }
		$sequence_4 = { e8???????? 83f801 7510 e8???????? e8???????? }
		$sequence_5 = { eb1a b8fdffffff eb13 b8fcffffff }
		$sequence_6 = { 8bb5f4fffdff 03b5f8fffdff c1ee03 8b4508 8b7810 }
		$sequence_7 = { 6810040000 ff15???????? 8985f4fbffff 83bdf4fbffff00 0f8488010000 8a0d???????? }
		$sequence_8 = { 83fa7b 750a 6a01 e8???????? }
		$sequence_9 = { 8b4dfc 894110 8b550c 8b420c c1e803 50 }
		$sequence_10 = { c745fcffffffff 8d45f4 64a300000000 c3 6a03 e8???????? 59 }
		$sequence_11 = { 7c62 8b8df8fffdff 0fb6940dfefffdff 83fa3a 7d4f 8b85f8fffdff }
		$sequence_12 = { 6bc02a 05???????? 50 e8???????? 83c40c 85c0 7509 }
		$sequence_13 = { 85c0 0f84b2000000 6a03 68???????? 8b8de0fbffff 83e90e }
		$sequence_14 = { 8884248e010000 b801000000 486bc03f 488d0d79e50100 0fbe0401 83f04d 8884248f010000 }
		$sequence_15 = { 488bcd 418bd7 e8???????? 33c9 85c0 0f85bb010000 4c8d35ee481900 }

	condition:
		7 of them and filesize <3964928
}