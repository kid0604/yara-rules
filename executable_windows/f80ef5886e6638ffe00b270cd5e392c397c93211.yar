rule win_stabuniq_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.stabuniq."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stabuniq"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 57 e8???????? 5b 81ebe7924000 }
		$sequence_1 = { 6a00 6a00 6a25 8d55ac 52 8b4508 05e8110000 }
		$sequence_2 = { 8b4838 51 8b5510 ff524c 50 8b450c }
		$sequence_3 = { 8b4518 0fbe88dc0e0000 85c9 7515 685cf94000 8b5518 81c2dc0e0000 }
		$sequence_4 = { c20400 55 8bec 8b4508 0518020000 50 }
		$sequence_5 = { 8b8d6cf9ffff 83e940 51 8b9528f9ffff 52 8d856cfaffff 50 }
		$sequence_6 = { 51 8b550c ff523c 8d45f8 50 }
		$sequence_7 = { 50 8b4d10 ff9184000000 6a02 8d95e4fcffff 52 8b4510 }
		$sequence_8 = { 8d8dc0fcffff 51 e8???????? 8b5508 83c220 895508 68ff000000 }
		$sequence_9 = { ff9188000000 8b95d8fdffff 52 8b4508 }

	condition:
		7 of them and filesize <57344
}
