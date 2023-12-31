rule win_webc2_cson_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.webc2_cson."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_cson"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { b9ff000000 33c0 8dbd01fcffff f3ab 66ab 6a00 }
		$sequence_1 = { eb4a 8d45c0 68???????? 50 }
		$sequence_2 = { b9ff090000 8dbdc1d6ffff 889dc0d6ffff f3ab 66ab aa }
		$sequence_3 = { 56 ff15???????? 56 ff15???????? ff75f0 e8???????? 83c41c }
		$sequence_4 = { 57 50 e8???????? 6a06 be???????? 57 }
		$sequence_5 = { 8945d8 ffd7 8b35???????? 50 ffd6 8b1d???????? 6a0f }
		$sequence_6 = { 56 53 e8???????? 85c0 7457 6800040000 8d8500fcffff }
		$sequence_7 = { 5e 5b 83c444 c3 55 8bec b88c900100 }
		$sequence_8 = { 83f840 72ec 0fbe4586 83f863 7f6f 7440 }
		$sequence_9 = { 83f801 754a 6800900100 8d85746ffeff 53 50 e8???????? }

	condition:
		7 of them and filesize <98304
}
