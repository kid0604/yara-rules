rule win_redyms_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.redyms."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redyms"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 32d8 80f3fb 8819 40 41 6683f805 72ee }
		$sequence_1 = { 8b4604 50 6a00 ffd3 50 ffd7 56 }
		$sequence_2 = { 33c5 8945fc 56 8b35???????? 8d4ddc 8bd1 }
		$sequence_3 = { 85f6 0f84e4000000 8b3d???????? 8d4de8 8bd1 33c0 }
		$sequence_4 = { a1???????? 33c5 8945fc 56 c785ccfeffff04010000 7203 }
		$sequence_5 = { c745d000000000 ff15???????? 5f 85c0 }
		$sequence_6 = { 7417 8b45f4 8b4df8 50 51 56 ff15???????? }
		$sequence_7 = { 8b4608 8b4e04 50 6a00 e8???????? 83c408 }
		$sequence_8 = { 83c8ff 5b 8be5 5d c3 8bc6 5f }
		$sequence_9 = { 8d5828 53 8945fc ffd7 83caff 8bc6 f00fc110 }

	condition:
		7 of them and filesize <98304
}