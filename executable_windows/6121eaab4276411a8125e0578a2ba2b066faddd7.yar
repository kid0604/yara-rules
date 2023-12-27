rule win_meow_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.meow."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.meow"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c685cefaffff53 c685cffaffff63 c685d0faffff53 c685d1faffff53 c685d2faffff53 8a85c9faffff e8???????? }
		$sequence_1 = { 72dc ff75ec 8d4599 50 e8???????? 8b33 ba0f000000 }
		$sequence_2 = { 0f8441070000 c745f4bb195c00 be03000000 8b45f4 99 f7fe 85d2 }
		$sequence_3 = { 99 f7f9 8b45f4 85d2 7403 48 eb01 }
		$sequence_4 = { 743b 8b45f0 83c117 83c00b 99 f7f9 8945f0 }
		$sequence_5 = { c685dbfdffff5f c685dcfdffff7d c685ddfdffff7d c685defdffff7d 8a85d5fdffff e8???????? 898564f5ffff }
		$sequence_6 = { 7907 48 83c8fc 83c001 7463 8b4c2410 8d4303 }
		$sequence_7 = { 8a01 8d4901 0fb6c0 83e871 6bc037 99 f7fb }
		$sequence_8 = { c6854dfeffff4c c6854efeffff3b c6854ffeffff6b c68550feffff3b c68551feffff26 c68552feffff3b c68553feffff18 }
		$sequence_9 = { 99 f7f9 85d2 7445 8b442410 8d4f17 83c00b }

	condition:
		7 of them and filesize <492544
}