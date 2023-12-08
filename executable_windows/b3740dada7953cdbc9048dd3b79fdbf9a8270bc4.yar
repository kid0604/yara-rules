rule win_sysraw_stealer_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.sysraw_stealer."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sysraw_stealer"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c74024ff030000 c74028ff070000 c7402cff0f0000 c74030ff1f0000 c74034ff3f0000 }
		$sequence_1 = { 33c9 8955bc 894de4 ba3f000000 3bca 0f8f0c020000 83f910 }
		$sequence_2 = { 8d45dc 50 68???????? 8d4dd0 }
		$sequence_3 = { 51 50 6880000000 53 }
		$sequence_4 = { 8d45bc 50 51 c745c401000000 c745bc02000000 ff15???????? 8b55d0 }
		$sequence_5 = { 8bd0 8d4de4 ffd6 b802000000 03d8 e9???????? 8d5590 }
		$sequence_6 = { 52 8b55e4 8b0490 8b9550feffff 50 52 56 }
		$sequence_7 = { ff512c 8b5590 8b8d5cfeffff b810000000 }
		$sequence_8 = { 8b06 ff5004 8b4d10 8b1d???????? 6a03 }
		$sequence_9 = { 8b55d0 03c7 50 52 ffd3 8bd0 }

	condition:
		7 of them and filesize <1540096
}
