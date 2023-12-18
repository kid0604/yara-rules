rule win_mrdec_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.mrdec."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mrdec"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c64446fa00 57 56 e8???????? 68???????? 56 e8???????? }
		$sequence_1 = { 6a00 8d45cc 50 68ef000000 68???????? }
		$sequence_2 = { 50 ff75f0 6a00 6a00 6a00 ff75e8 e8???????? }
		$sequence_3 = { 7532 68dc050000 ff75dc 68???????? e8???????? }
		$sequence_4 = { 6a00 6814010000 68???????? ff75d8 e8???????? 8d3550514000 }
		$sequence_5 = { 8bec ff7508 6a40 e8???????? 0bc0 750c 68c8000000 }
		$sequence_6 = { 81c700020000 68???????? 57 e8???????? 68???????? 57 e8???????? }
		$sequence_7 = { 59 51 80c141 884808 ff05???????? 6a00 6a00 }
		$sequence_8 = { 6a02 e8???????? 0bc0 0f8530010000 c745f000400000 ff75f0 }
		$sequence_9 = { 6a00 6a00 e8???????? ff75dc e8???????? }

	condition:
		7 of them and filesize <44864
}
