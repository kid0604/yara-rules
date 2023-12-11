rule win_lockbit_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.lockbit."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lockbit"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 894f08 89570c f745f800000002 740c 5f 5e }
		$sequence_1 = { 8d8550fdffff 50 6a00 ff15???????? }
		$sequence_2 = { 6a00 6a00 6800000040 ff75d4 }
		$sequence_3 = { f266af f7d1 49 8bc1 5f 59 }
		$sequence_4 = { 56 57 33c0 8b5d14 33c9 33d2 }
		$sequence_5 = { 5b 8907 897704 894f08 89570c 837df001 }
		$sequence_6 = { 75d8 8bc2 5e 5a 59 }
		$sequence_7 = { 53 56 57 33c0 8d7df0 33c9 }
		$sequence_8 = { 33d0 8bc1 c1e810 0fb6c0 c1e208 }
		$sequence_9 = { 6a02 ff750c ff7508 6a00 }
		$sequence_10 = { 53 50 e8???????? 85c0 7479 53 }
		$sequence_11 = { 51 57 6633c0 83c9ff 8b7d08 }
		$sequence_12 = { 32c1 aa e9???????? 5f }
		$sequence_13 = { 66833f20 74f7 8d857cffffff 50 57 e8???????? ff750c }
		$sequence_14 = { 33c0 8d7df0 33c9 53 0fa2 8bf3 5b }
		$sequence_15 = { 0f28c8 660f73f904 660fefc8 0f28c1 660f73f804 }
		$sequence_16 = { 8d45f8 50 8d45fc 50 ff75fc ff75f4 }
		$sequence_17 = { 6683e857 eb14 6683f830 720c 6683f839 }

	condition:
		7 of them and filesize <2049024
}
