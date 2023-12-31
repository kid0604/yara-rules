rule win_anatova_ransom_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.anatova_ransom."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.anatova_ransom"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 4c89da 4c8b1d???????? 41ffd3 488b45d8 4989c3 }
		$sequence_1 = { 488d0d8c570000 4801c1 0fb601 83f055 8801 ebd8 b814010000 }
		$sequence_2 = { 8908 488b05???????? 488b4d18 488908 b800000300 4989c3 }
		$sequence_3 = { ebde 8b45d8 4863c0 488d0d8c570000 }
		$sequence_4 = { 4839c1 0f832a000000 e9???????? 8b4584 4889c1 83c001 894584 }
		$sequence_5 = { b80a000000 8885f1feffff b80e000000 8885f2feffff b80c000000 8885f3feffff }
		$sequence_6 = { 8b4df8 01c8 4863c0 488b4d20 4801c1 }
		$sequence_7 = { b800000000 8945fc 8b45fc 83f80a 0f8d24000000 e9???????? 8b45fc }
		$sequence_8 = { 4989c0 b800000000 4989c3 488b05???????? 4989c2 4c89d1 }
		$sequence_9 = { b812000000 4989c3 4989ca 4c89d1 }

	condition:
		7 of them and filesize <671744
}
