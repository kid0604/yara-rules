rule win_misha_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.misha."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.misha"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0f95c3 84db 7460 8b7518 85f6 740d }
		$sequence_1 = { 8b4518 56 57 c745e4080a0e18 c745e81e304160 c645ec82 83f808 }
		$sequence_2 = { 8b45fc 0fb680a0000000 2580000000 7517 8b45fc 0fb680a1000000 2580000000 }
		$sequence_3 = { 0f8481000000 6a05 ff7510 8d7de4 8b7508 e8???????? 59 }
		$sequence_4 = { 8b7c2428 41 83e808 41 f7d8 1bc0 41 }
		$sequence_5 = { e9???????? 8b450c 2b45f0 894580 8b45e0 2b4580 50 }
		$sequence_6 = { eb41 8b45f4 8b4004 83c810 8b4df4 894104 8b45ec }
		$sequence_7 = { 48 e9???????? 837d1800 7422 33c0 40 741d }
		$sequence_8 = { c3 56 ff742408 8bf0 56 e8???????? ff742410 }
		$sequence_9 = { e8???????? 59 8d45a4 50 8b4310 83c030 50 }

	condition:
		7 of them and filesize <710656
}
