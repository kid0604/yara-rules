rule win_odinaff_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.odinaff."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.odinaff"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 3d1f040000 7505 bf01000000 }
		$sequence_1 = { 740c 57 6a00 ffd3 50 ff15???????? 6a00 }
		$sequence_2 = { 6a08 33ff 57 57 ff15???????? }
		$sequence_3 = { 8bd8 ff15???????? 53 6a00 6a00 56 ff15???????? }
		$sequence_4 = { 49 81c900ffffff 41 8a8138474000 }
		$sequence_5 = { 8b1d???????? 83c40c 6820bf0200 56 ffd3 b900000800 2bc8 }
		$sequence_6 = { c745dc01000000 e8???????? 6a44 8d4580 53 50 e8???????? }
		$sequence_7 = { 7508 ff15???????? eb7b 6a04 }
		$sequence_8 = { e8???????? 8b45f8 83c410 85c0 7408 50 6a00 }
		$sequence_9 = { 8b4d0c 6a00 6880000000 6a02 }

	condition:
		7 of them and filesize <73728
}
