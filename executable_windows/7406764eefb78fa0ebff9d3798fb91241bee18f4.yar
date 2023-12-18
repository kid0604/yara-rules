rule win_feed_load_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.feed_load."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.feed_load"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 48897c2428 4d8bc5 41b940200000 e8???????? 85c0 0f84e2000000 }
		$sequence_1 = { 0f97c1 493bd2 eb27 4c8d42ff 418a00 4d8d4c24ff 413801 }
		$sequence_2 = { 41898500400000 488bfd 4d8bfa bd01000000 83fb0d 0f8c42030000 41690ab179379e }
		$sequence_3 = { 668928 e8???????? 4c8d86500c0000 488bcf e8???????? 4c8d442440 488bcf }
		$sequence_4 = { 7876 3b1d???????? 736e 488bc3 488bf3 48c1fe06 4c8d2d7a220200 }
		$sequence_5 = { 0f8c60040000 41837e0800 4c8d05b755ffff 7429 49635608 48035608 0fb60a }
		$sequence_6 = { 8bd5 ff15???????? 448bc5 488bd6 488bc8 4c8bf0 }
		$sequence_7 = { 488bc2 4903c7 4103df 803800 75f5 3bdf 7207 }
		$sequence_8 = { 4c8d3de9c00100 49393cdf 7402 eb22 e8???????? 498904df }
		$sequence_9 = { 488d157b020200 488d4d88 e8???????? cc }

	condition:
		7 of them and filesize <512000
}
