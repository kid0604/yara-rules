rule win_lazardoor_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.lazardoor."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lazardoor"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 488bd1 488bc1 48c1f806 4c8d05f4f60000 }
		$sequence_1 = { 428a8c3998a50100 482bd0 8b42fc d3e8 443bc8 0f8d09010000 488b4b28 }
		$sequence_2 = { 4053 4883ec20 488d05575a0100 488bd9 488901 f6c201 740a }
		$sequence_3 = { 8905???????? 0f1105???????? 8b15???????? 4533c9 488b0d???????? 4533c0 }
		$sequence_4 = { 4d85c0 7410 488d15615b0200 488bc8 }
		$sequence_5 = { 44392d???????? 743d 4533c9 4c896c2430 c744242880000000 }
		$sequence_6 = { 660f6e5cc610 660f62d8 660f6fc7 660f6cda 660ffec4 660f76de }
		$sequence_7 = { 33d2 e8???????? 3bc3 7565 03fb 8b1d???????? 3bfb }
		$sequence_8 = { ba5a540000 e9???????? 8b05???????? 85c0 }
		$sequence_9 = { 4c8bc1 b84d5a0000 66390525b6ffff 7578 48630d58b6ffff 488d1515b6ffff 4803ca }

	condition:
		7 of them and filesize <405504
}
