rule win_woody_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.woody."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.woody"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c744241001000080 50 6819000200 6a00 68a8ac0110 6801000080 ff15???????? }
		$sequence_1 = { 85ff 0f843e040000 8b06 8bcf 8d542410 2bc8 53 }
		$sequence_2 = { 50 894c2420 51 b9e8ca0110 e8???????? 8b4c241c 83f911 }
		$sequence_3 = { bf00000080 8b4c0450 3bca 7423 39540464 751d 8b5d04 }
		$sequence_4 = { 50 ffd6 83c410 3bc3 7402 8818 8d8530fdffff }
		$sequence_5 = { 56 57 b931000000 33c0 8dbc24f1000000 c68424f000000000 f3ab }
		$sequence_6 = { 3975ec 7524 8d45dc 50 8d45d4 50 8d45cc }
		$sequence_7 = { 8b4c2450 2bc8 8d442444 50 898c247c030000 ff15???????? }
		$sequence_8 = { 8b442410 50 8b10 ff5208 8b742420 8d842430020000 50 }
		$sequence_9 = { 395ddc 7442 395dcc 743d 395dc4 7438 3bc3 }

	condition:
		7 of them and filesize <409600
}
