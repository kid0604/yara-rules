rule win_eyservice_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.eyservice."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.eyservice"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b7c2418 57 8bce e8???????? 8b4f04 8b86a4000000 8b3f }
		$sequence_1 = { 8d942424090000 68???????? 52 ff15???????? 83c408 57 85c0 }
		$sequence_2 = { 8d4e04 e8???????? c744241400000000 e8???????? 8d462c 50 c706ffffffff }
		$sequence_3 = { e9???????? 8b35???????? 57 6aff 68???????? 6aff 8d542474 }
		$sequence_4 = { 5e 5d 8d42f9 5b 59 c20400 8b7c2418 }
		$sequence_5 = { 6a00 52 50 55 ff15???????? 89460c 83f8ff }
		$sequence_6 = { 52 6a00 68???????? 50 c744242408020000 c744242801000000 ffd3 }
		$sequence_7 = { 2bf0 7424 3bf1 7602 8bf1 8b4f0c }
		$sequence_8 = { 8a8ee4000000 80f902 7318 57 8b3d???????? 90 6a01 }
		$sequence_9 = { 8b74240c 8b462c 33db 57 3bc3 7415 }

	condition:
		7 of them and filesize <452608
}
