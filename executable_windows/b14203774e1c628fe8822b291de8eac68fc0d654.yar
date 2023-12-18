rule win_yayih_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.yayih."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yayih"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 5f ff7508 ff55f4 53 ff15???????? 8bc7 }
		$sequence_1 = { 68???????? e8???????? 8b35???????? 83c40c 50 57 }
		$sequence_2 = { 50 56 e8???????? 59 85c0 59 753c }
		$sequence_3 = { 85c0 59 7507 57 e8???????? 59 e8???????? }
		$sequence_4 = { ff15???????? 56 6880000000 6a03 56 6a01 8d85b8b8ffff }
		$sequence_5 = { 66ab aa 59 33c0 8dbde9faffff 889de8faffff f3ab }
		$sequence_6 = { 3bfe 750a 56 56 56 6a08 }
		$sequence_7 = { e8???????? 6801200000 8d85b8b8ffff 56 50 e8???????? }
		$sequence_8 = { 50 8d854cf6ffff 50 e8???????? 83c430 8d459c 50 }
		$sequence_9 = { 0fafca 0fb65002 03ca 890d???????? 0fb64803 69c960ea0000 }

	condition:
		7 of them and filesize <57344
}
