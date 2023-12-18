rule win_gaudox_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.gaudox."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gaudox"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7403 c60000 8bce e8???????? 8b45f8 85c0 7410 }
		$sequence_1 = { 837df000 0f849a000000 6a00 8d95c4feffff 52 b804000000 6bc800 }
		$sequence_2 = { 8d8c2458030000 e8???????? 8bf0 85f6 0f88df000000 a1???????? 8d8c2450030000 }
		$sequence_3 = { a1???????? 57 ffb0b8000000 eb26 8bb8b0000000 83ff54 }
		$sequence_4 = { 13c9 66f3ab 8b450c 03f0 8bc6 5f 5e }
		$sequence_5 = { 56 8b7014 81feb8000000 7729 68???????? b9???????? e8???????? }
		$sequence_6 = { ff75fc 8bf0 6a08 6a00 e8???????? 85f6 782a }
		$sequence_7 = { 8b45f4 8b5018 85d2 74ec 6a00 6a00 68d113282e }
		$sequence_8 = { 57 85c0 0f84ad010000 85d2 0f84a5010000 8b7d08 85ff }
		$sequence_9 = { 8d442460 50 6a27 6a00 e8???????? 85c0 781c }

	condition:
		7 of them and filesize <155648
}
