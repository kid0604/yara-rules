rule win_goopic_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.goopic."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.goopic"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 68???????? ffd6 57 ff15???????? 8b4dfc }
		$sequence_1 = { 8945fc 56 57 8d85fcf7ffff 8bf1 }
		$sequence_2 = { ff15???????? 83bdf0efffff00 7409 83bdf8efffff00 77a4 }
		$sequence_3 = { ffb5f8f7ffff ff15???????? ffb5f8f7ffff ff15???????? 8b4dfc 33c0 33cd }
		$sequence_4 = { 8d4910 660f70c000 83c004 660ffec1 f30f7f41f0 }
		$sequence_5 = { 68???????? 8d85fcf7ffff 50 ff15???????? 6a02 68???????? ff15???????? }
		$sequence_6 = { 83c40c 83c704 83fe14 72e6 be01000000 ff75e4 ff15???????? }
		$sequence_7 = { 8b848dfcfbffff 03f0 81e6ff000080 7908 4e }
		$sequence_8 = { 50 8d85f8dfffff 50 ffd7 85c0 }
		$sequence_9 = { ff35???????? ffd3 85c0 7477 68???????? e8???????? }

	condition:
		7 of them and filesize <114688
}
