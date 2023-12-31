rule win_reaver_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.reaver."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.reaver"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 50 ff15???????? 85c0 7453 8d45f4 50 }
		$sequence_1 = { 7440 8b45f4 6a00 8945e8 }
		$sequence_2 = { 50 68ff010f00 ff15???????? 50 ff15???????? 85c0 7453 }
		$sequence_3 = { c3 55 8bec 83ec1c 8d45fc 50 68ff010f00 }
		$sequence_4 = { ff15???????? 85c0 7440 8b45f4 6a00 }
		$sequence_5 = { 85c0 7440 8b45f4 6a00 }
		$sequence_6 = { 50 ff7508 6a00 ff15???????? 85c0 7440 }
		$sequence_7 = { 6a00 ff15???????? 85c0 7440 8b45f4 6a00 }
		$sequence_8 = { 83ec1c 8d45fc 50 68ff010f00 ff15???????? }
		$sequence_9 = { 83ec1c 8d45fc 50 68ff010f00 ff15???????? 50 }

	condition:
		7 of them and filesize <106496
}
