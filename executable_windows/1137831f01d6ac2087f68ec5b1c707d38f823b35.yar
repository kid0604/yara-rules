rule win_deputydog_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.deputydog."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.deputydog"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8d85c0fdffff 6a08 50 8d043e 50 e8???????? 83c430 }
		$sequence_1 = { 6a01 8d4e04 ff15???????? 8b4df4 5e }
		$sequence_2 = { ff15???????? 8b461c 8b00 83c008 8b4004 }
		$sequence_3 = { 8bce 895dfc e8???????? 85c0 7508 885d0f }
		$sequence_4 = { 50 8d4514 50 e8???????? e9???????? 6a01 5b }
		$sequence_5 = { 8d85a4fbffff 50 ffd6 8b4dfc 83c410 8d85a4fbffff 50 }
		$sequence_6 = { ff15???????? 8b450c 8b4004 eb05 a1???????? 85ff 0f8ec5000000 }
		$sequence_7 = { 57 53 8d4dd8 8845d8 ff15???????? bf???????? 57 }
		$sequence_8 = { 6a01 a3???????? 58 c20c00 b8???????? }
		$sequence_9 = { 50 ff15???????? 8d858cfdffff 68???????? }

	condition:
		7 of them and filesize <90112
}
