rule win_killdisk_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.killdisk."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.killdisk"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83c404 3bdd 744c 57 }
		$sequence_1 = { 57 bb07000000 68???????? 8d742438 895c2450 897c244c }
		$sequence_2 = { 0f825cffffff 57 e8???????? 83c404 8b442408 50 }
		$sequence_3 = { e8???????? 9c 8f442420 ff3424 ff742424 8f4500 }
		$sequence_4 = { 0f8544ffffff 83f810 8b44242c 8974243c }
		$sequence_5 = { 8d542414 52 ff15???????? 3974240c 73c6 5f }
		$sequence_6 = { 8f442420 ff3424 660fb6f3 5e e8???????? 66ffc6 e8???????? }
		$sequence_7 = { 75f2 51 e8???????? 83c404 5f }
		$sequence_8 = { 8b11 8910 83c004 894608 5f }
		$sequence_9 = { 8b0d???????? 668b15???????? 8908 66895004 8bc3 }
		$sequence_10 = { 68540d40df 60 896c2434 e8???????? 8b4500 60 68c46a8e46 }
		$sequence_11 = { 51 e8???????? 4e 80fcd7 60 f5 f6d0 }
		$sequence_12 = { e9???????? ff742404 66894500 886c2408 9c 66c70424306b }
		$sequence_13 = { e9???????? 880424 8774242c 9c }
		$sequence_14 = { 66894500 ff3424 9c 6689742404 8d642450 e9???????? 89442424 }
		$sequence_15 = { 6816cc2923 46 66892c24 9c 8d64244c e9???????? 9c }

	condition:
		7 of them and filesize <10817536
}
