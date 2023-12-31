rule win_findpos_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.findpos."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.findpos"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 48 0f844b050000 33c0 8d8c24f0010000 50 51 8d8c243c020000 }
		$sequence_1 = { 68???????? e8???????? a1???????? 59 59 83c010 a3???????? }
		$sequence_2 = { 7671 8365d400 8d55d4 8bcf }
		$sequence_3 = { 8bcf e8???????? 8325????????00 833d????????10 68???????? 0f4335???????? }
		$sequence_4 = { 8b0cb8 03cb e8???????? 85c0 7414 8b4df0 }
		$sequence_5 = { eb29 8a01 3c33 7505 }
		$sequence_6 = { 8945f8 8d45f8 50 c745ec00200000 ff15???????? 85c0 745f }
		$sequence_7 = { 3b08 7518 53 51 51 6a01 8d45e4 }
		$sequence_8 = { 50 0fb6c1 50 8d85e8e7ffff 50 }
		$sequence_9 = { 33f6 46 3bc6 0f8577040000 6a11 ffd7 663bc6 }

	condition:
		7 of them and filesize <286720
}
