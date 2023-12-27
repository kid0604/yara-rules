rule win_kwampirs_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.kwampirs."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kwampirs"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 50 8d45f0 64a300000000 8965e8 8bf9 33db }
		$sequence_1 = { e8???????? b001 8b4df0 64890d00000000 59 }
		$sequence_2 = { 51 e8???????? 83c404 a3???????? 33f6 }
		$sequence_3 = { 3bf3 7642 56 e8???????? 8907 }
		$sequence_4 = { 668955f4 33d2 668955f6 e8???????? 83c40c }
		$sequence_5 = { c3 32c0 8b4df0 64890d00000000 59 }
		$sequence_6 = { 8d4df0 51 68???????? e8???????? 83c40c 32c0 }
		$sequence_7 = { 6a00 6800001000 6a03 6a00 }
		$sequence_8 = { 83c404 8a45e7 8b4df0 64890d00000000 59 5f }
		$sequence_9 = { 33c5 50 8d45f0 64a300000000 8965e8 8bf9 33db }

	condition:
		7 of them and filesize <2695168
}