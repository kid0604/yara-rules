rule win_zumanek_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.zumanek."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zumanek"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7c8b e45f 22f9 17 c8914c74 8bc4 5f }
		$sequence_1 = { 96 44 b6d9 89fe }
		$sequence_2 = { ef 5a c0eb87 a805 }
		$sequence_3 = { 52 d34045 58 894d2c 3d5bf2aba3 48 }
		$sequence_4 = { 94 1298249c48a0 91 a4 22a844acb089 b412 b824c048c8 }
		$sequence_5 = { 324613 03aa6a75464a a1???????? 1cd2 3133 }
		$sequence_6 = { d3b9193b75fb 105945 9c 22dc b004 ae }
		$sequence_7 = { c8be45f2 2f 91 7c89 4a 17 48 }
		$sequence_8 = { 0e 3d83b538a4 f77306 9abb1d94786f4f 08cd }
		$sequence_9 = { 01e9 b052 ac dd09 40 fc 42 }

	condition:
		7 of them and filesize <58867712
}
