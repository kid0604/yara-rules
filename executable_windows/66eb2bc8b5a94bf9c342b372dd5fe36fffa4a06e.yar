rule win_fancyfilter_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.fancyfilter."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fancyfilter"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 740a 66833800 7404 b001 eb02 }
		$sequence_1 = { a1???????? 83c012 50 ff15???????? }
		$sequence_2 = { 8b07 83e810 50 83c610 56 }
		$sequence_3 = { ff15???????? 83c420 83f803 7409 83f806 }
		$sequence_4 = { 83c012 50 ffd6 a1???????? }
		$sequence_5 = { 85c0 750d 8b472c a801 7406 83c804 }
		$sequence_6 = { 85c0 740a 66833800 7404 b001 eb02 }
		$sequence_7 = { 81e3ffffff00 ff15???????? 50 ff15???????? }
		$sequence_8 = { 85c0 740a 66833800 7404 b001 }
		$sequence_9 = { b805400080 c20400 56 8b742408 }

	condition:
		7 of them and filesize <169984
}