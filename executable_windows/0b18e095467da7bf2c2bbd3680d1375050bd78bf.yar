rule win_op_blockbuster_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.op_blockbuster."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.op_blockbuster"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8a08 80f920 7505 83c021 }
		$sequence_1 = { 56 57 683c400000 6a40 ff15???????? }
		$sequence_2 = { f3ab 66ab aa 5f 85f6 }
		$sequence_3 = { ff15???????? 6808400000 6a40 ff15???????? }
		$sequence_4 = { 56 e8???????? 68???????? 56 a3???????? e8???????? 83c440 }
		$sequence_5 = { e8???????? 85c0 7407 83f802 }
		$sequence_6 = { 8b497c 85c9 7407 51 }
		$sequence_7 = { 56 50 8d45fc 6a04 50 }
		$sequence_8 = { 85c0 7412 68???????? 50 e8???????? 59 a3???????? }
		$sequence_9 = { 3c69 7c08 3c70 7f04 0409 eb06 3c72 }
		$sequence_10 = { 57 ff15???????? 8bc6 5f 5e c3 33c0 }
		$sequence_11 = { 85c0 748d ff15???????? 488b5c2460 33c0 4883c450 }
		$sequence_12 = { 4885c0 0f8480010000 4c89b424e8030000 4c89bc24e0030000 448bf3 b800400000 }
		$sequence_13 = { e8???????? 4881c4c0040000 415f 5f 5e 5b 5d }
		$sequence_14 = { 56 6a00 ff15???????? 8bf8 85ff 7504 }
		$sequence_15 = { 5e c3 68???????? ff15???????? 85c0 7412 }
		$sequence_16 = { 8bf0 ff15???????? 85f6 7404 85c0 }
		$sequence_17 = { 57 e8???????? 56 e8???????? 83c414 b801000000 }
		$sequence_18 = { 0f1f840000000000 0fb603 48ffc3 88441aff 84c0 75f2 488d542450 }
		$sequence_19 = { 488907 83c8ff 488b8c24f0030000 4833cc e8???????? 488b9c2420040000 4881c400040000 }
		$sequence_20 = { c3 56 53 6a01 57 e8???????? 56 }
		$sequence_21 = { 6bd23c 03d0 8b05???????? 6bc03c 0305???????? 3bc2 7f17 }
		$sequence_22 = { 68???????? 56 e8???????? 56 e8???????? 83c438 }
		$sequence_23 = { ebf8 53 33db 391d???????? 56 }
		$sequence_24 = { 488bc8 ff15???????? 488d4d00 4489642464 488bd8 4489642468 }
		$sequence_25 = { 7edd 83c8ff 85c0 7831 8b1cc5ac324400 6a55 }
		$sequence_26 = { 8b461c 83f808 0f8499000000 83f807 0f87a0000000 ff2485d2164100 }
		$sequence_27 = { 741c 81f900000400 7542 0c80 88441628 8b04bdd8974400 c644102901 }
		$sequence_28 = { e8???????? 8d8c2414040000 51 6a66 }
		$sequence_29 = { 8975d8 8b08 52 57 50 }
		$sequence_30 = { ebda 8bb5dcfdffff eb02 33f6 57 ff15???????? }
		$sequence_31 = { 668b45f8 66894610 668b45fa 66894612 668b85f8feffff }
		$sequence_32 = { 50 68???????? 68???????? 8d8514f2ffff 68???????? 50 }
		$sequence_33 = { 897dec e8???????? 59 8945f4 }

	condition:
		7 of them and filesize <74309632
}
