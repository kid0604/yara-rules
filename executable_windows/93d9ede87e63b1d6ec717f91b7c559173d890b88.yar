rule win_blackcoffee_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.blackcoffee."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackcoffee"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8d85b4feffff 50 ff75f8 ff15???????? 8b85b4feffff }
		$sequence_1 = { 8b35???????? 57 33ff 3bc7 7416 57 50 }
		$sequence_2 = { 8b45fc 83c424 8d44301a 6a1c 6a40 894508 ff15???????? }
		$sequence_3 = { 890d???????? ebdb 89848a00c0e7ff a1???????? ff05???????? }
		$sequence_4 = { e8???????? ff36 e8???????? 83c00c 68444e4549 }
		$sequence_5 = { 8d856cffffff c7856cffffff94000000 50 ff15???????? 6a05 }
		$sequence_6 = { c20800 55 8bec 81ec98000000 56 57 }
		$sequence_7 = { 899d30ffffff 66895df0 f3ab 8d7df2 6a0f }
		$sequence_8 = { 83c00c 0107 8b37 03f3 e8???????? 6854414449 }
		$sequence_9 = { 57 c7460404100680 897e0c 894614 ff75f8 53 ff15???????? }

	condition:
		7 of them and filesize <118784
}
