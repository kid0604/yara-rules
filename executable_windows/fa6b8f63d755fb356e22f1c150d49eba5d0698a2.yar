rule win_ramnit_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.ramnit."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ramnit"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8bec 83c4f8 56 57 51 53 }
		$sequence_1 = { 5a 5b c9 c20c00 b800000000 }
		$sequence_2 = { 8b45fc 03450c 66bb0000 668918 8b45fc }
		$sequence_3 = { 55 8bec 53 52 51 57 }
		$sequence_4 = { 3b450c 7603 8b450c c9 }
		$sequence_5 = { f3aa 5e 5f 59 c9 }
		$sequence_6 = { 8a4510 f2ae 4f 8a07 3a4510 }
		$sequence_7 = { 8bf8 037d14 3b7df8 771f 8945fc ff7514 ff7510 }
		$sequence_8 = { 8bc1 f7d0 48 59 }
		$sequence_9 = { c9 c20c00 b800000000 59 5f 5e }

	condition:
		7 of them and filesize <470016
}