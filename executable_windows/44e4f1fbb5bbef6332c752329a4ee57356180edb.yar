rule win_chthonic_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.chthonic."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chthonic"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { d3ee 83e601 8975fc eb00 85ff 0f84bd000000 4f }
		$sequence_1 = { eb00 85f6 74cb 8b75f8 }
		$sequence_2 = { 83c703 013e 8b36 83c410 f60680 }
		$sequence_3 = { 8845ff 8d84bdfcfbffff 8b10 8911 }
		$sequence_4 = { 0301 03f8 81e7ff000080 7908 4f 81cf00ffffff }
		$sequence_5 = { 83e601 eb00 8b4df8 8d0c4e }
		$sequence_6 = { 6a2a 58 ff7508 66894108 b8ecff0000 }
		$sequence_7 = { d3ee 83e601 eb00 85f6 74cb 8b75f8 83fe02 }
		$sequence_8 = { 013e 8b36 83c410 f60680 7408 }
		$sequence_9 = { 46 8908 3bf3 7cbc 33db 33f6 33ff }

	condition:
		7 of them and filesize <425984
}