rule win_bluelight_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.bluelight."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bluelight"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e9???????? 8d4dd8 e9???????? 8d4da4 e9???????? 8d4db0 e9???????? }
		$sequence_1 = { eb04 2bc6 8bf0 81fe00280000 7605 33ff 47 }
		$sequence_2 = { 8b4728 895ddc c60701 8945fc 0f8e77010000 8b00 8365e400 }
		$sequence_3 = { eb15 33d2 8bce e8???????? eb0a 807e0505 7504 }
		$sequence_4 = { ff7594 50 e8???????? 83c410 837da800 7421 837da000 }
		$sequence_5 = { e8???????? 8b45fc f7401c00400000 7426 8bce e8???????? eb16 }
		$sequence_6 = { ff770c e8???????? 83c414 8944240c 53 e8???????? 8b5c2410 }
		$sequence_7 = { eb13 8b442410 33d2 6a00 8bc8 897018 e8???????? }
		$sequence_8 = { 8bd8 894df4 8b4610 8b440804 8945ec 85c0 742c }
		$sequence_9 = { ff770c e8???????? 8b550c 8bcf 6aff e8???????? 6a00 }

	condition:
		7 of them and filesize <2191360
}
