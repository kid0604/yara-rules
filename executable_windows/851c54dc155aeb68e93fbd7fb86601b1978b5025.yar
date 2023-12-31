rule win_phandoor_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.phandoor."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phandoor"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0f8411010000 833d????????00 0f8404010000 833d????????00 0f84f7000000 }
		$sequence_1 = { 0f84f7000000 833d????????00 0f84ea000000 833d????????00 0f84dd000000 }
		$sequence_2 = { 895df8 8b8e9c010000 53 51 ff15???????? 8b55f8 }
		$sequence_3 = { 8b8eb8010000 890d???????? 8b96bc010000 8915???????? }
		$sequence_4 = { 57 8855ff 894df4 8bf8 397508 766d 53 }
		$sequence_5 = { 8d45f4 68???????? 50 8bf9 c645f400 c745f500000000 e8???????? }
		$sequence_6 = { c1e818 8d0c3f 33cf 32d3 32d0 8b45f4 81e1fe010000 }
		$sequence_7 = { 50 ffd3 8bf8 3bfe 8b35???????? 0f8491050000 b9???????? }
		$sequence_8 = { 3b7e08 7d5f 8b06 8b0cb8 51 e8???????? 83c404 }
		$sequence_9 = { 33c0 3b35???????? 7327 57 }
		$sequence_10 = { 56 8975e0 895dec 895dfc }
		$sequence_11 = { 837e0c00 740c e8???????? c7460c00000000 }
		$sequence_12 = { 57 8d7e10 57 ff15???????? 83c604 e8???????? 57 }
		$sequence_13 = { 740b 8a4601 46 43 84c0 7409 }
		$sequence_14 = { 50 c705????????03000000 ffd6 8b0d???????? 33ff 57 }
		$sequence_15 = { 837e0400 8d5e04 c706???????? 7431 837e0c00 740c }

	condition:
		7 of them and filesize <2124800
}
