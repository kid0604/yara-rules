rule win_quickheal_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.quickheal."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.quickheal"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7ce2 b814010000 8a8c28f8feffff 888c0484000000 40 3d30010000 72ea }
		$sequence_1 = { 3bf3 0f840b030000 8d4e02 8d542424 51 }
		$sequence_2 = { ff15???????? 8d542410 8d8424fc060000 52 6819000200 53 }
		$sequence_3 = { 49 51 6a06 52 ffd5 83c408 }
		$sequence_4 = { 2bce 51 56 50 56 e8???????? 83c410 }
		$sequence_5 = { 8d445d0c 83c408 33f6 6683f93b }
		$sequence_6 = { 83c102 3bc6 7cf0 5f }
		$sequence_7 = { 7207 885101 04fc eb04 c6410100 3c02 7209 }
		$sequence_8 = { f7d1 49 8dbc2414010000 8bd1 83c9ff f2ae a1???????? }
		$sequence_9 = { 52 ffd7 85c0 7418 8b442410 c744241404010000 50 }

	condition:
		7 of them and filesize <553984
}