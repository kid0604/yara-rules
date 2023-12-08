rule win_olympic_destroyer_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.olympic_destroyer."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.olympic_destroyer"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 56 33c0 89542414 57 }
		$sequence_1 = { ff75e4 ff15???????? 68???????? bb???????? e8???????? bb???????? }
		$sequence_2 = { 85c0 740e 50 e8???????? 83a660ee550000 59 }
		$sequence_3 = { 50 8975f8 ffd3 ff75f8 6a08 }
		$sequence_4 = { b8???????? c744242400000000 c744241400000000 c7442418d0f25500 c744243800000000 3910 }
		$sequence_5 = { 742e 50 6a40 ff15???????? 89442408 85c0 741d }
		$sequence_6 = { ff75ec ffd3 85c0 740c 8b45f0 ff700c ff15???????? }
		$sequence_7 = { 50 68???????? 6a01 56 e8???????? 83c424 ba58000000 }
		$sequence_8 = { 7412 f7c300000040 7506 89742410 eb04 8974240c 8b15???????? }
		$sequence_9 = { 8b85ecefffff 8b8de8efffff 3bc6 7d0c }
		$sequence_10 = { 50 6880000000 e8???????? 83c40c eb5d }
		$sequence_11 = { 8d1c2f 3bda 7765 8b442414 8bf7 }
		$sequence_12 = { e8???????? 8904bd60ee5500 85c0 7514 6a0c 5e 8975e4 }
		$sequence_13 = { 50 6880000000 ff7310 ff15???????? }
		$sequence_14 = { 89442424 8d54241c 8b842490000000 8d4c2424 8944241c 0fb744242e }
		$sequence_15 = { 50 68???????? 8901 ff770c }
		$sequence_16 = { 8975fc 8975f4 8975dc ffd3 ff75fc 8b3d???????? 6a08 }
		$sequence_17 = { 50 68???????? 6a17 6a00 68???????? 8bf9 }
		$sequence_18 = { 8d5eec 53 ff15???????? 85c0 }
		$sequence_19 = { 53 ff15???????? 53 ff15???????? 33c0 8b4dfc 5f }
		$sequence_20 = { 50 68???????? 8bd7 8bcb e8???????? 8bd8 }
		$sequence_21 = { 50 68???????? 6a1b e8???????? 83c410 83fbff 0f8514010000 }
		$sequence_22 = { 50 56 ff15???????? 85c0 742e 6aff }

	condition:
		7 of them and filesize <1392640
}
