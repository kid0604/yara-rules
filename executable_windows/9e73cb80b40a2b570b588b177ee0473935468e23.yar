rule win_lowball_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.lowball."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lowball"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 33c0 8dbc2425030000 c684242403000000 f3ab 66ab 8d8c2424030000 }
		$sequence_1 = { 83c408 85f6 746c 6a02 }
		$sequence_2 = { f2ae f7d1 49 8be9 8b842434020000 68???????? 50 }
		$sequence_3 = { 85c0 0f8452010000 a1???????? 8a0d???????? 89842420020000 }
		$sequence_4 = { 68???????? e8???????? 8b1d???????? 83c410 85c0 752d }
		$sequence_5 = { 8bd8 ff15???????? 56 57 6a01 }
		$sequence_6 = { 57 ff15???????? 57 89442444 e8???????? }
		$sequence_7 = { 8d842428020000 8bcb 50 83e103 68???????? 68???????? f3a4 }
		$sequence_8 = { 85f6 7420 8b542410 56 52 8d84242c020000 }
		$sequence_9 = { 8bfa 8d94241c010000 c1e902 f3a5 8bc8 8d442418 }

	condition:
		7 of them and filesize <40960
}
