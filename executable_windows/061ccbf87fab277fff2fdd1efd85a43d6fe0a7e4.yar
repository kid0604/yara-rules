rule win_trochilus_rat_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.trochilus_rat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.trochilus_rat"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0fb74636 50 ffd7 0fb7c8 668bd1 662b935e010100 }
		$sequence_1 = { 6a32 56 53 e8???????? }
		$sequence_2 = { 50 ffd3 668b8e52010100 662bc8 6683f903 0f8c9e000000 81863001010018fcffff }
		$sequence_3 = { 56 8bf1 8d5e04 8bcb e8???????? 83f8ff 7407 }
		$sequence_4 = { 8d4de4 51 50 ff7538 ff7534 }
		$sequence_5 = { 5e 5d c20c00 55 8bec 837d08ff 56 }
		$sequence_6 = { 68???????? 50 ff15???????? 85c0 7404 33c0 eb1a }
		$sequence_7 = { ff15???????? 33c0 eb81 55 8bec 51 53 }
		$sequence_8 = { 33db 391f 7e1d 8b4704 8b4c0304 68a01e0110 e8???????? }
		$sequence_9 = { b8fac50010 e8???????? 8bf1 837d0800 7505 8b06 ff505c }

	condition:
		7 of them and filesize <630784
}
