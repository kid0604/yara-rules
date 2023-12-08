rule win_micrass_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.micrass."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.micrass"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 57 ff750c ff750c ffb5a83fffff 6aff 68???????? 56 }
		$sequence_1 = { 6801001f00 ff15???????? 3bc3 0f857c020000 56 53 }
		$sequence_2 = { 8a807c194000 08443b1d 0fb64601 47 3bf8 }
		$sequence_3 = { b81c600000 e8???????? a1???????? 33c5 8945fc ff750c }
		$sequence_4 = { ff15???????? 85c0 0f84fb000000 8d85bc3fffff 50 }
		$sequence_5 = { 35d3000000 8b8d14faffff 88840df4fcffff ebc8 }
		$sequence_6 = { 6a05 59 be???????? 8dbd0cfdffff }
		$sequence_7 = { 898504faffff 8b8508faffff 668b00 66898502faffff 838508faffff02 6683bd02faffff00 }
		$sequence_8 = { 48 49 75f1 33c9 66890c451ad94000 68???????? 56 }
		$sequence_9 = { 33c5 8945fc ff7508 8d85e04fffff 56 50 e8???????? }

	condition:
		7 of them and filesize <163840
}
