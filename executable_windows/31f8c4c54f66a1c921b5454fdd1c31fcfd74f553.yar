rule win_gibberish_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.gibberish."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gibberish"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83c10c e9???????? 8b4de0 83c11c e9???????? 8b4de0 83c144 }
		$sequence_1 = { 3334c5f3a94700 8bc2 c1e810 0fb6c0 0fb688c8a94500 8bc2 }
		$sequence_2 = { 33c8 8bc6 c1c806 33c8 8b442424 33442428 }
		$sequence_3 = { 53 8bd9 895c2404 57 c703???????? 83f808 }
		$sequence_4 = { 8d45b0 50 e8???????? 83c404 ff7768 8d4dc8 }
		$sequence_5 = { 80f939 0f8f9a050000 0fbe46ff ff348508ad4500 }
		$sequence_6 = { 8955b8 894db0 8975b4 85c0 7514 68???????? }
		$sequence_7 = { 83c30c c645fc01 817b0455555505 8b3b 0f8493000000 8b4704 8945e8 }
		$sequence_8 = { 8b7508 6a0a 50 8d4590 898d78ffffff 50 c7458c00000000 }
		$sequence_9 = { 660fdbd9 660fdbe1 f30f7ef6 0f28cd 660fdbf2 b802000000 0f28542440 }

	condition:
		7 of them and filesize <1068032
}
