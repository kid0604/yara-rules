rule win_darkme_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.darkme."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkme"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8dbddcfcffff f3ab b964000000 8dbd18fbffff 68???????? 8985d8fcffff 8985d4fcffff }
		$sequence_1 = { 51 8d55d4 52 6a02 ff15???????? 83c40c 8d45c4 }
		$sequence_2 = { 8b8518ffffff 8b08 8b9518ffffff 52 ff5114 dbe2 }
		$sequence_3 = { 6a00 ff15???????? 50 8b558c 81c2???????? 52 ff15???????? }
		$sequence_4 = { c745880a000000 8b8530ffffff 50 ff15???????? 8945a0 c7459808000000 8b4dd4 }
		$sequence_5 = { 8b8500ffffff 50 8b8dfcfeffff 51 ff15???????? 898594feffff eb0a }
		$sequence_6 = { 05???????? 898588feffff eb12 8b8db4feffff 81c1???????? 898d88feffff 8b9588feffff }
		$sequence_7 = { 83c42c 51 68???????? ff15???????? 85c0 0f851afeffff }
		$sequence_8 = { 8b5144 52 8d8524ffffff 50 8d8d54ffffff 51 ff15???????? }
		$sequence_9 = { 8b08 8b95fcfeffff 52 ff5120 }

	condition:
		7 of them and filesize <1515520
}
