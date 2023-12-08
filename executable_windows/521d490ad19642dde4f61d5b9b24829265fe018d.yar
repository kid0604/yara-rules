rule win_silon_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.silon."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.silon"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83c404 0345d0 50 e8???????? 83c408 8945cc 837dcc00 }
		$sequence_1 = { 837df400 743e 8b4dfc 51 8b55f4 52 }
		$sequence_2 = { 6a00 68???????? ff15???????? 8945f8 837df800 0f8cdf000000 8d4df0 }
		$sequence_3 = { 85c0 7518 8b4dd4 51 68???????? 68???????? }
		$sequence_4 = { 83b82c08000000 7437 8b4df8 83b93008000000 752b 8b55f8 }
		$sequence_5 = { e8???????? 83c40c 6a03 8b5508 52 8d45e0 50 }
		$sequence_6 = { 8b4508 83b85808000002 0f8688000000 8b4d08 8b9154080000 0fbe02 83f81f }
		$sequence_7 = { e9???????? 837dfc00 7514 837d1400 0f84be000000 837d1801 0f86b4000000 }
		$sequence_8 = { c7804808000000000000 8b4dfc 83c104 51 8b5508 52 e8???????? }
		$sequence_9 = { e8???????? 83c404 8d440002 50 8b4d08 51 }

	condition:
		7 of them and filesize <122880
}
