rule win_sysget_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.sysget."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sysget"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 56 6a20 8d45cc 50 53 53 }
		$sequence_1 = { f3a5 33f6 8d4435f0 8a08 f6d1 80f15f }
		$sequence_2 = { 58 6a00 ff15???????? 6a01 8d85ecf9ffff 50 8d85ecf1ffff }
		$sequence_3 = { 8985c8f9ffff 83c032 50 66a5 e8???????? 83c428 }
		$sequence_4 = { 33f6 8d4435f0 8a08 f6d1 80f15f 46 }
		$sequence_5 = { 75f5 8dbdecfeffff 2bc2 83ef02 668b4f02 83c702 6685c9 }
		$sequence_6 = { 83c424 6800010000 ffb5f8feffff c1e306 8d841dfcfeffff 50 ff15???????? }
		$sequence_7 = { 6a50 68???????? 50 ff15???????? a3???????? a1???????? }
		$sequence_8 = { 51 ff36 897d0c 50 53 }
		$sequence_9 = { 8d459c 50 56 56 6a20 53 }

	condition:
		7 of them and filesize <352256
}
