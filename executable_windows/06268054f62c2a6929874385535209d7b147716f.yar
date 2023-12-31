rule win_action_rat_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.action_rat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.action_rat"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8d4d0c e8???????? 8b4508 8b4df4 64890d00000000 59 5b }
		$sequence_1 = { 8b55f8 52 8b4dfc 83c134 e8???????? 8b00 50 }
		$sequence_2 = { 83c270 52 8b4dfc 83c170 }
		$sequence_3 = { e8???????? c745d400000000 eb09 8b4dd4 83c101 894dd4 8d4d0c }
		$sequence_4 = { 7420 0fb645fb 50 8b4df4 8b4918 e8???????? 0fb6d0 }
		$sequence_5 = { 0fb74202 50 ff15???????? 0fb7c8 8b5514 890a }
		$sequence_6 = { 6a00 8b45fc 50 8b4d08 51 e8???????? 83c418 }
		$sequence_7 = { e8???????? 8d8ddcfbffff e8???????? c645fc0e 6a00 68e0930400 6a00 }
		$sequence_8 = { 0de0000000 b901000000 6bd100 8b4d0c 880411 8b5508 c1fa06 }
		$sequence_9 = { 8b4df4 3b4df8 750b 68???????? ff15???????? 8b55ec 833a22 }

	condition:
		7 of them and filesize <480256
}
