rule win_funny_dream_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.funny_dream."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.funny_dream"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c785e0ddffff01000000 50 6880000000 68ffff0000 ffb3c0000000 }
		$sequence_1 = { 6a00 ff7728 ffd6 6a00 ff7724 ff15???????? 8b4714 }
		$sequence_2 = { c745d45368656c 50 53 c745d86c457865 c745dc63757465 66c745e04100 }
		$sequence_3 = { 85c0 0f8494000000 33c9 8a840d3cffffff }
		$sequence_4 = { ff15???????? 85c0 0f85e7feffff 8d4704 899da0fdffff }
		$sequence_5 = { 6a00 6800040000 8d842458030000 50 }
		$sequence_6 = { 50 57 ff15???????? 85c0 7523 8b4618 8b3d???????? }
		$sequence_7 = { 50 ff15???????? 8d442408 c744240810000000 50 8d442414 0f57c0 }
		$sequence_8 = { 85c0 0f84f8000000 68???????? 50 ff15???????? }
		$sequence_9 = { 83c404 8b4f04 85c9 7504 33c0 eb05 8b4708 }

	condition:
		7 of them and filesize <393216
}
