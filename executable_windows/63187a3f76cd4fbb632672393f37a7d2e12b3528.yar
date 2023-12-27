rule win_socelars_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.socelars."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.socelars"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { eb4e 8b4dec e8???????? 8b00 8b4d08 8d14c8 8955d4 }
		$sequence_1 = { f7df c744243401000000 83d300 f7db 895c2428 eb14 8b4508 }
		$sequence_2 = { 8d0cc1 8b472c 8901 8b471c 894104 0fbf4720 894108 }
		$sequence_3 = { c7471000000000 83bed400000000 741d 8bcf e8???????? 8bd8 85db }
		$sequence_4 = { ff15???????? 8b450c 85c0 750f 80fb01 720a 8bce }
		$sequence_5 = { e8???????? 8bc8 8b9514feffff b808000000 66894108 8b8514feffff 8b4010 }
		$sequence_6 = { c645f701 8b4df8 894de8 8d55f7 52 8d45ef 50 }
		$sequence_7 = { 8b9514feffff 8b8d04feffff 8b8508feffff 83c214 e9???????? 8b4928 e8???????? }
		$sequence_8 = { f30fe6c0 f20f5cc8 f20f59cd 8806 46 8b442428 83e801 }
		$sequence_9 = { c744881000000000 895714 834f0820 8b442430 8d4c244c 51 8b4c241c }

	condition:
		7 of them and filesize <2151424
}