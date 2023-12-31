rule win_cycbot_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.cycbot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cycbot"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 59 8b45ec e8???????? c3 6834020000 b8???????? e8???????? }
		$sequence_1 = { 57 ffb5e8feffff ff15???????? 8bb5ecfeffff 2bf3 f7de 1bf6 }
		$sequence_2 = { c745dc44eb4300 c745e08ceb4300 c745e40cee4300 c745e820ee4300 c745ec34ee4300 c745f0f4ec4300 c745f4fcec4300 }
		$sequence_3 = { 8b06 8b4008 89480c 8b06 894808 8b4508 8908 }
		$sequence_4 = { 59 33c0 8d7dc8 f3ab aa 8d45c8 6a21 }
		$sequence_5 = { 33c0 8903 894304 57 894308 ff15???????? c70300000000 }
		$sequence_6 = { 8d854cfbffff 50 8bc7 e8???????? 59 59 57 }
		$sequence_7 = { ff5108 8d85e0fbffff 50 ff15???????? ff85d8fbffff 39bdb4fbffff }
		$sequence_8 = { 50 e8???????? 837c241801 59 59 7408 c744241807000000 }
		$sequence_9 = { b90a0a0000 663b4c07fe 7508 8945fc be01000000 40 }

	condition:
		7 of them and filesize <1163264
}
