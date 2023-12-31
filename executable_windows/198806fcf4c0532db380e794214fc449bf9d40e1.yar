rule win_abaddon_pos_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.abaddon_pos."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.abaddon_pos"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 80beb401000002 750f 80beb801000001 7506 }
		$sequence_1 = { 83f80c 7702 eb05 e9???????? 31db c786ac01000000000000 }
		$sequence_2 = { 48 c7c1f4010000 ff15???????? 48 83c420 48 }
		$sequence_3 = { 8908 83c008 8d95e4feffff 52 50 ff15???????? 6a00 }
		$sequence_4 = { 80fa5e 741c 80fa3d 7417 80fa00 7612 80fa7c }
		$sequence_5 = { 48 89d9 48 c7c280000000 ff15???????? }
		$sequence_6 = { 0faf45f4 03855cfeffff 6800d00700 50 ff15???????? }
		$sequence_7 = { 8986b8050000 48 83f800 0f844e030000 48 }
		$sequence_8 = { 8b9ec8050000 48 8918 48 83c008 }
		$sequence_9 = { 48 83c420 48 8b86d0050000 48 0500040000 }
		$sequence_10 = { c786e4050000c2a510a5 66c786e2050000456b 66c786e00500000200 48 8b86d0050000 }
		$sequence_11 = { 7402 eb68 8b5d08 81c300040000 53 ff15???????? }
		$sequence_12 = { 7508 6a05 ff15???????? 8b86a0010000 3b86a4010000 0f83e6030000 }
		$sequence_13 = { ff15???????? 6a1c 8d9600010000 52 ff15???????? 6a1c 8d9600010000 }
		$sequence_14 = { 48 8b8ec0050000 48 c7c200000000 ff15???????? 48 83c420 }
		$sequence_15 = { 48 83c000 48 8b9eb8050000 48 }

	condition:
		7 of them and filesize <40960
}
