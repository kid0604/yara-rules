rule win_banatrix_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.banatrix."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.banatrix"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 897dcc 7514 8b7304 83b88400000000 }
		$sequence_1 = { ebd4 8b4320 893c24 89442404 }
		$sequence_2 = { 8b5704 0310 8b450c 83e00f 48 83f8ff 7409 }
		$sequence_3 = { 0f45f9 8b4e10 85c9 7514 a840 7405 8b4a20 }
		$sequence_4 = { 56 53 83ec10 8b5d08 85db 0f849c000000 837b1000 }
		$sequence_5 = { c7042415070000 e8???????? 50 31c0 eb6f }
		$sequence_6 = { eb20 8b7514 39f0 7306 c6040300 }
		$sequence_7 = { 8b4508 6681384d5a 7409 c70424c1000000 eb78 8b5d08 }
		$sequence_8 = { 8b4514 8b1a 668945e2 8b7204 83bb8c00000000 7509 c7042414070000 }
		$sequence_9 = { 89c7 89c1 c1ef1f 897dcc 89c7 }

	condition:
		7 of them and filesize <180224
}
