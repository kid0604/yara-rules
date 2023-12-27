rule win_bankshot_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.bankshot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bankshot"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8bf8 8d5101 8a01 41 84c0 75f9 57 }
		$sequence_1 = { 81ec48040000 a1???????? 33c5 8945f8 53 }
		$sequence_2 = { 83c40c e8???????? 99 b907000000 }
		$sequence_3 = { 680c400000 8d8528beffff 6a00 50 e8???????? 0f280d???????? }
		$sequence_4 = { c74048b8e40110 8b4508 6689486c 8b4508 66898872010000 8b4508 83a04c03000000 }
		$sequence_5 = { 3bf7 7cc8 eb04 3bf7 7c99 8d8de4fdffff }
		$sequence_6 = { 8bd0 83c408 83faff 7474 33c0 85d2 }
		$sequence_7 = { e9???????? 6915????????04010000 8d8dbc3affff 68???????? 81c2???????? e8???????? }
		$sequence_8 = { c700???????? 8b4508 898850030000 8b4508 59 c74048b8e40110 }
		$sequence_9 = { 83c404 85c0 0f84fe080000 680c400000 }
		$sequence_10 = { e8???????? 83c404 89861c020000 8b45e0 8d4e0c 6a06 8d90c4e10110 }
		$sequence_11 = { 8d856438ffff 2bf1 50 ff15???????? 89854038ffff 8b4308 0f10853838ffff }
		$sequence_12 = { 50 e8???????? 83c40c 6b45e430 8945e0 8d80d0e10110 }
		$sequence_13 = { e9???????? 57 33ff 8bcf 8bc7 894de4 3998c0e10110 }
		$sequence_14 = { 4b 7515 8b45fc 817848b8e40110 7409 ff7048 e8???????? }
		$sequence_15 = { 83f869 7c27 8b8df8fbffff 0fbe11 83fa70 }
		$sequence_16 = { 3bf3 0f8244ffffff 33c0 85db 0f841b010000 }
		$sequence_17 = { 8b442418 8d0c00 51 6a40 ff15???????? }
		$sequence_18 = { 4883c420 415c c3 4053 56 4154 4883ec20 }
		$sequence_19 = { 85c0 741b 488d510c 448bc0 833a00 418bc7 }
		$sequence_20 = { 8bc6 83e03f 6bc830 8b0495c87f0110 f644082801 }
		$sequence_21 = { 8b10 8b8dc0fbffff 8b02 ffd0 8985a4fbffff }
		$sequence_22 = { 72dc 8b45fc 3b45f8 77d4 8b45fc 0345f0 }
		$sequence_23 = { 52 8b8568f8ffff 50 ff15???????? 8d8d78f8ffff 51 }
		$sequence_24 = { 33c0 8dbe70af0400 89ae6caf0600 f3ab 668b04dd62734100 33c9 }
		$sequence_25 = { ff15???????? 8b7c2478 8bf0 eb1b 8b7c2478 57 }
		$sequence_26 = { 50 e8???????? 83c418 8985acfbffff e9???????? 8b0d???????? }
		$sequence_27 = { 8b0485c8887100 c644082900 740e ff33 e8???????? 8bf0 }
		$sequence_28 = { 68e9fd0000 ff95f4f3ffff 33c0 8d8df8f7ffff 83bf1004000000 }
		$sequence_29 = { 89442420 ff15???????? b801000000 4883c438 c3 ff25???????? }
		$sequence_30 = { 440fb7448202 0fb71482 e8???????? 488d058653ffff }
		$sequence_31 = { 8bec 8b4508 57 8d3c85b87e0110 }
		$sequence_32 = { c744242001000000 e8???????? 85c0 7449 488d0d72850000 }
		$sequence_33 = { e8???????? 83c40c eb12 8d542404 }
		$sequence_34 = { 53 ff95ccfbffff 6800040000 8d85e4fbffff 6a00 }
		$sequence_35 = { 3bdf 7325 660f1f440000 ff15???????? }
		$sequence_36 = { 85c0 7508 8d7001 e9???????? 8d8424b8100000 }
		$sequence_37 = { ff15???????? 8b0d???????? 6a01 8d542414 }
		$sequence_38 = { 7531 e8???????? 8904bd80f10110 85c0 7514 6a0c }
		$sequence_39 = { 52 56 68???????? 68???????? 68???????? 53 }
		$sequence_40 = { 51 53 ff15???????? 85c0 7548 b903000000 8bfd }
		$sequence_41 = { 8b049580f10110 804c182d04 ff4604 eb08 ff15???????? }
		$sequence_42 = { 33c9 894de5 894de9 894ded 66894df1 }
		$sequence_43 = { 48895c2408 57 4883ec20 488d1d33220000 488d3d2c220000 }
		$sequence_44 = { 50 ff95c4f3ffff 85c0 7416 b801000000 }

	condition:
		7 of them and filesize <860160
}