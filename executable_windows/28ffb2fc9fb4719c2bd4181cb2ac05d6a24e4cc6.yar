rule win_matrix_banker_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.matrix_banker."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.matrix_banker"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { eb0b 8d4abf 80f905 7703 }
		$sequence_1 = { 8d489f 80f905 7704 04a9 eb0a 8d48bf }
		$sequence_2 = { 8d4a9f 80f905 7705 80c2a9 eb0b }
		$sequence_3 = { 7705 80c2a9 eb0b 8d4abf 80f905 7703 80c2c9 }
		$sequence_4 = { 80f905 7702 04c9 8d4ad0 }
		$sequence_5 = { 80c2a9 eb0b 8d4abf 80f905 7703 80c2c9 }
		$sequence_6 = { ff15???????? e8???????? 85c0 740a e8???????? 83f8ff }
		$sequence_7 = { eb18 8d4a9f 80f905 7705 80c2a9 }
		$sequence_8 = { eb18 8d4a9f 80f905 7705 }
		$sequence_9 = { 8d489f 80f905 7704 04a9 eb0a 8d48bf 80f905 }

	condition:
		7 of them and filesize <422912
}