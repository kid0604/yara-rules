rule win_stegoloader_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.stegoloader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stegoloader"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { f7db 1bdb f7d3 235dfc 3bdf 7409 }
		$sequence_1 = { 4a 75f0 8a043e 46 84c0 7669 0fb6c0 }
		$sequence_2 = { 59 eb32 8bc8 837db806 }
		$sequence_3 = { 59 7422 43 3b5e14 76e2 ff45fc 837dfc02 }
		$sequence_4 = { 0f84f9010000 c645a443 c645a54d c645a644 }
		$sequence_5 = { c645e968 c645ea65 c645eb6c c645ec6c c645ed5f c645ee54 c645ef72 }
		$sequence_6 = { 7415 ff75f4 8bcb ff7604 }
		$sequence_7 = { 8d0481 8b0438 03c7 3bc6 720e 8b4df0 03ce }
		$sequence_8 = { ff742414 8bce ff5004 84c0 }
		$sequence_9 = { 03df 8b03 03c7 33c9 3808 7407 }
		$sequence_10 = { 8d0448 0fb70438 eb07 662b5e10 0fb7c3 8b4e1c }
		$sequence_11 = { 83c604 4b 890411 75db eb0a }
		$sequence_12 = { 33db 56 668945f4 83c002 33f6 3bd3 }
		$sequence_13 = { 7e68 8b4d0c 8b4508 53 56 57 8b7d10 }
		$sequence_14 = { 7409 8b01 6a01 ff10 897d0c }
		$sequence_15 = { 8a4510 f6d8 1bc0 83e004 894510 e8???????? 3bc3 }

	condition:
		7 of them and filesize <802816
}