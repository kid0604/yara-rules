rule win_conficker_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.conficker."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.conficker"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ebe4 f60638 75a8 b008 d0ef 1400 }
		$sequence_1 = { df6de8 51 df6df8 51 }
		$sequence_2 = { 8bec 83ec20 8b0d???????? a1???????? 8365f800 56 }
		$sequence_3 = { 3c04 7415 42 42 60 b066 f2ae }
		$sequence_4 = { c3 6a10 68???????? e8???????? 68???????? ff15???????? }
		$sequence_5 = { 3345f8 33c7 33c6 50 ff15???????? 59 5f }
		$sequence_6 = { 8b4508 33d2 8910 895004 33c9 894c8808 41 }
		$sequence_7 = { 8d85f8fbffff ff7510 50 e8???????? }
		$sequence_8 = { 8954241c 61 c3 ac }
		$sequence_9 = { 55 8bec 83ec20 8b0d???????? a1???????? }

	condition:
		7 of them and filesize <335872
}
