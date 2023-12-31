rule win_konni_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.konni."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.konni"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 52 8d45dc 50 6a00 68???????? 51 ff15???????? }
		$sequence_1 = { 53 56 57 8b7d10 8985f4feffff 33f6 }
		$sequence_2 = { 7908 4e 81ce00ffffff 46 8a9435f8feffff 88940df8feffff }
		$sequence_3 = { d0f9 0fbef1 83e601 8970f4 }
		$sequence_4 = { 8bec 83ec24 a1???????? 33c5 8945fc 8b0d???????? 8a15???????? }
		$sequence_5 = { 884c15f4 8970e8 42 83c020 83fa03 }
		$sequence_6 = { 8a4c15f4 0fbef1 83e601 897004 }
		$sequence_7 = { 6a3d 68???????? 53 e8???????? }
		$sequence_8 = { 6a01 ff15???????? 50 a3???????? e8???????? }
		$sequence_9 = { 68b6030000 6a0d 50 ff15???????? }
		$sequence_10 = { 56 e8???????? 8a9435dec44600 5e 84c0 8bfa }
		$sequence_11 = { e8???????? 8a8c30a6c44600 5e 8b442414 03ca 03c1 }
		$sequence_12 = { 50 ff15???????? 8d85f8feffff 50 ff15???????? 68???????? 8d8df8feffff }
		$sequence_13 = { e8???????? 8a9c30c2c44600 5e 83f908 7232 8b4e04 }
		$sequence_14 = { 57 56 ff95b10f0000 ab b000 }
		$sequence_15 = { 8b35???????? 8d95f0faffff 52 8d85f8feffff }
		$sequence_16 = { 8d8df0faffff 51 ffd6 8b35???????? 8d95f0faffff }
		$sequence_17 = { c1e902 83e203 83f908 7229 f3a5 ff2495f0444000 8bc7 }
		$sequence_18 = { 4c89742420 ff15???????? 488bd8 4885c0 744f }
		$sequence_19 = { 33c9 56 e8???????? 8a8c30a6c44600 }
		$sequence_20 = { 51 ff15???????? 85c0 755b 57 }
		$sequence_21 = { 56 e8???????? 8a8c30dec44600 5e }
		$sequence_22 = { 6a00 6a00 ff15???????? 68d0070000 ff15???????? 8b4dfc }
		$sequence_23 = { ffd6 6804010000 8d85f0fcffff 50 68???????? ff15???????? }
		$sequence_24 = { 50 ff95b50f0000 898598040000 8bf0 8d7d51 57 56 }
		$sequence_25 = { 68???????? 8d85f8feffff 50 ffd6 68???????? 8d8df0faffff 51 }
		$sequence_26 = { 50 038594040000 59 0bc9 89851a040000 }
		$sequence_27 = { 48895c2450 4889442458 4889442460 4585e4 7456 }
		$sequence_28 = { 488b5618 4883cbff 4885d2 0f847e010000 }
		$sequence_29 = { 4d03e5 3918 0f4c18 3bcb 0f8d87000000 488d3d53e40000 ba58000000 }
		$sequence_30 = { 44884304 41f7e9 c1fa02 8bc2 c1e81f 03d0 }
		$sequence_31 = { 488d05581a0100 483bc8 741a 83b96001000000 7511 e8???????? 488b8b58010000 }
		$sequence_32 = { 488b742460 4885f6 0f8458010000 4c89642470 }
		$sequence_33 = { eb1f 8bce 83e61f c1f905 8bc6 8b0c8de0a30010 8d04c0 }
		$sequence_34 = { 83c42c 5f eb26 8d4508 8db644830010 6a00 }
		$sequence_35 = { 48895c2408 4889742410 48897c2418 4154 4883ec20 4c8d2578c80000 33f6 }
		$sequence_36 = { 8bf1 c1e603 3b9640830010 0f851c010000 }
		$sequence_37 = { 0fb645c1 8845bd 0fb645c5 884dc5 0fb64dba 8845c1 }
		$sequence_38 = { 83f908 7229 f3a5 ff2495585a0010 8bc7 ba03000000 83e904 }
		$sequence_39 = { b800000004 e9???????? 488d1528e7ffff 488d4c2440 }
		$sequence_40 = { 83c40c 837dfc0d 7476 837dfc08 7470 }
		$sequence_41 = { 488d8180030000 483918 75f1 4889b980030000 33c0 }
		$sequence_42 = { 6a03 ff15???????? c3 56 be???????? }
		$sequence_43 = { e8???????? cc 488b5210 488bcb ff15???????? 488905???????? }
		$sequence_44 = { 0f8489000000 4533db 488d35b44d0100 0f1f4000 488b4350 }
		$sequence_45 = { 0f1f8000000000 b9e8030000 ff15???????? 4533c9 48895c2430 488d4de0 }
		$sequence_46 = { 498b0f 4889442468 0fb68540050000 4c8d1da7510000 }

	condition:
		7 of them and filesize <330752
}
