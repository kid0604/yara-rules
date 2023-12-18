rule win_c0d0so0_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.c0d0so0."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.c0d0so0"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 895dfc 8975f4 ff15???????? ff75f8 }
		$sequence_1 = { 7404 0006 eb02 2806 0fb6c0 03d0 03f0 }
		$sequence_2 = { 807e0d00 c6460801 7469 8b460e 8b1d???????? 8365f800 83c012 }
		$sequence_3 = { 53 8b5f04 c745f401000000 0f86f4000000 56 8bb080000000 6a14 }
		$sequence_4 = { 83c204 83f914 7ceb 8bc7 8b4dfc 33cd }
		$sequence_5 = { 752c 6a01 56 e8???????? 59 59 }
		$sequence_6 = { 50 33ff ff15???????? 8d4598 50 ff15???????? }
		$sequence_7 = { ff7334 ffd6 8945fc 85c0 }
		$sequence_8 = { 3acb 75f6 8bc7 5f 5e }
		$sequence_9 = { 33ff 53 47 e8???????? 59 eb0b 56 }

	condition:
		7 of them and filesize <450560
}
