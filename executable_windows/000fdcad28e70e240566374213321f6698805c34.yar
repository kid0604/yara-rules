rule win_shadowpad_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.shadowpad."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shadowpad"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 897e04 8b4608 3bc7 740d 50 e8???????? 59 }
		$sequence_1 = { c3 6a0d 58 5f c3 }
		$sequence_2 = { 8d45f8 50 8d45e8 e8???????? 8a4586 8845f8 8d45f8 }
		$sequence_3 = { 8b442440 2b442410 8b4c2444 1b4c2414 781e }
		$sequence_4 = { 8d742458 e8???????? 5f 5e 33c0 }
		$sequence_5 = { 803c0700 7403 47 ebba 8b4d08 33c0 }
		$sequence_6 = { 33db be00000100 56 e8???????? 59 8d4df8 }
		$sequence_7 = { e8???????? 8b45e8 6a02 5b }
		$sequence_8 = { 50 47 e8???????? 85c0 75c3 }
		$sequence_9 = { 32d1 46 8810 3b7508 0f8c74ffffff 5f }

	condition:
		7 of them and filesize <188416
}
