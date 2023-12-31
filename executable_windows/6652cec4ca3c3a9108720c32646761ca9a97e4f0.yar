rule win_brambul_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.brambul."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.brambul"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 85f6 7509 8db42448030000 eb01 46 }
		$sequence_1 = { 5d b810000000 5b 81c440050000 }
		$sequence_2 = { 80a0a099400000 40 41 41 3bc6 72bf eb49 }
		$sequence_3 = { 0bef 8bfb 33fa 23fd }
		$sequence_4 = { ffd6 50 53 ffd7 50 ffd5 }
		$sequence_5 = { 8b7d90 8b458c 8b4d88 83c410 3bf8 7307 8bd0 }
		$sequence_6 = { 56 b053 8d7324 57 88442410 }
		$sequence_7 = { 6a00 6a00 ffd7 83c418 6a32 ffd6 4b }
		$sequence_8 = { 0bcb 8bdf f7d3 03ca 0bd9 }
		$sequence_9 = { 7505 804c247401 55 8bcb e8???????? 85c0 }
		$sequence_10 = { 8b15???????? 89442440 a0???????? 894c2450 8b0d???????? }
		$sequence_11 = { 897d90 c745ec01000000 8b558c 8365f800 3bfa 895dfc 897508 }
		$sequence_12 = { 83c410 85c0 0f8590010000 8d442428 8d4c2430 50 57 }
		$sequence_13 = { 8945dc 7605 8945fc 8bd0 6a01 8913 }
		$sequence_14 = { 0bce 8bf1 33f5 33f2 03f3 8dbc37a1ebd96e }
		$sequence_15 = { 03c7 8d942486000000 8d0c8510202f00 51 52 ffd6 8b44242c }

	condition:
		7 of them and filesize <188416
}
