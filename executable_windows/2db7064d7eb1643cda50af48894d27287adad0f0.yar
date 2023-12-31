rule win_doorme_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.doorme."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.doorme"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 488d1591220100 448bc6 488bcf e8???????? 85c0 }
		$sequence_1 = { 66443920 7417 4c8bc7 418d542416 488d0d6f3d0100 e8???????? 488b0b }
		$sequence_2 = { e8???????? 85c0 7466 488d15f5550100 488d4d60 e8???????? 85c0 }
		$sequence_3 = { 85c9 7858 3b15???????? 7350 488bca 4c8d051d840200 83e13f }
		$sequence_4 = { e8???????? 488b05???????? 488d156dfa0200 488bcd }
		$sequence_5 = { 458d81134630a8 0bc8 418bc2 034c2420 4403d9 41c1c307 }
		$sequence_6 = { e8???????? 90 660f6f05???????? f30f7f8580010000 }
		$sequence_7 = { 4883f81f 0f87e4010000 498bc8 e8???????? 49897f10 49c747180f000000 }
		$sequence_8 = { 48c7c03f000000 23c1 488d0d4abb0100 f20f5904c1 f20f5804c1 660f72e406 660f73f434 }
		$sequence_9 = { 4983e901 75d2 488bc3 448d4204 6666660f1f840000000000 }

	condition:
		7 of them and filesize <580608
}
