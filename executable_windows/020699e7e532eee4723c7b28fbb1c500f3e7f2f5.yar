rule win_hancitor_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.hancitor."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hancitor"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6a00 6a00 6824040000 6a00 6a00 6a00 }
		$sequence_1 = { 6800010000 6a40 68???????? e8???????? 83c40c }
		$sequence_2 = { 8b5508 03513c 8955e0 b808000000 c1e000 }
		$sequence_3 = { 8b11 8955d8 8b45f0 8b4804 894de8 8b5508 }
		$sequence_4 = { 33c0 eb0f 8b450c 50 ff15???????? }
		$sequence_5 = { 41 3bc8 72f7 c6043000 40 }
		$sequence_6 = { 55 8bec 8b4508 8078013a }
		$sequence_7 = { 83fbff 7509 6a00 57 }
		$sequence_8 = { 8b4d14 51 8d5510 52 8b450c 50 }
		$sequence_9 = { 894dec 8b55ec 3b55d4 7352 8b45f8 }
		$sequence_10 = { a1???????? 85c0 740c ff7508 6a00 }
		$sequence_11 = { 33f6 03c8 6a40 6800300000 }
		$sequence_12 = { 8b4d08 6a00 6a01 51 8b413c 8b440828 03c1 }
		$sequence_13 = { 7502 5d c3 ff7508 6a00 50 ff15???????? }
		$sequence_14 = { 035128 8b4518 8910 eb02 eb2d 6a00 8b4df0 }
		$sequence_15 = { 8b11 52 6a00 ff15???????? 85c0 7407 }
		$sequence_16 = { b9382baa99 c745f464000000 8b45cc 0305???????? 8945cc }
		$sequence_17 = { 05d3aa0d00 8945ec 8b45d0 40 8945d0 }
		$sequence_18 = { a3???????? 8b45f8 40 40 8945f8 }
		$sequence_19 = { 8b45b8 48 8945b8 a1???????? 83c044 }
		$sequence_20 = { a3???????? b9382baa99 8d45fc 50 6a00 }
		$sequence_21 = { 83c044 a3???????? b9382baa99 c7458ce4f25701 ff15???????? 894da0 a1???????? }
		$sequence_22 = { a3???????? 8b45a0 05c8d45566 7440 }
		$sequence_23 = { a3???????? 817df8b07d0900 0f8ced000000 a1???????? a3???????? b9382baa99 }

	condition:
		7 of them and filesize <106496
}
