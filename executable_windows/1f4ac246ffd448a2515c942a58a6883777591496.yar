rule win_wipbot_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.wipbot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wipbot"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { eb05 b8???????? e8???????? 89da 83c9ff e8???????? }
		$sequence_1 = { 5b 5d e9???????? 5a 31c0 5b 5d }
		$sequence_2 = { 4c 8d442428 baff010f00 48 89d9 ffd0 48 }
		$sequence_3 = { b911000000 31c0 c644245e2e 31d2 f3aa c644245f0b c64424601f }
		$sequence_4 = { 85c0 48 89c6 0f94c2 48 85db 0f94c0 }
		$sequence_5 = { 8d44245f 88d1 48 01d0 48 ffc2 3208 }
		$sequence_6 = { eb7d 48 894c2438 e8???????? 01c0 ba9ad65fb0 b98a758b1f }
		$sequence_7 = { 8d55f4 89542408 8d55f0 c744240c00800000 89542404 c70424ffffffff ffd0 }
		$sequence_8 = { 89cb b91d000000 c64424222e f3aa c644242379 c644242446 31c0 }
		$sequence_9 = { 8944240c 8b45a8 83c020 890424 ffd2 85c0 0f9fc0 }

	condition:
		7 of them and filesize <253952
}
