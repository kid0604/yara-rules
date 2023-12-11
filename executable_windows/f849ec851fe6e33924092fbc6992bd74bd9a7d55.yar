rule win_nefilim_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.nefilim."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nefilim"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 68???????? 50 ffd6 85c0 0f84fa000000 }
		$sequence_1 = { 00c0 3640 00e4 3640 0023 d18a0688078a }
		$sequence_2 = { 83c410 6a0f 58 803c07ff }
		$sequence_3 = { 8945fc 68???????? 8d4508 8d4de0 e8???????? 83781408 59 }
		$sequence_4 = { c3 55 8bec 83e4f8 81ecec020000 a1???????? }
		$sequence_5 = { 7304 8d442414 68???????? 50 ffd6 85c0 0f8482000000 }
		$sequence_6 = { ffd6 85c0 0f84cc030000 68???????? 8d8424d0000000 }
		$sequence_7 = { ff74241c ffd7 53 8d442434 50 56 }
		$sequence_8 = { e8???????? 59 8b4d08 8bd6 e8???????? 8bc6 }
		$sequence_9 = { 59 e9???????? 51 53 ff15???????? 50 }

	condition:
		7 of them and filesize <142336
}
