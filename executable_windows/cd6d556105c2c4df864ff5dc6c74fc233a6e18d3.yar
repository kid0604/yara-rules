rule win_daxin_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.daxin."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.daxin"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 2bc2 d1f8 99 f7f9 }
		$sequence_1 = { ff15???????? 488b0d???????? 483bcb 7458 895c2448 48895c2440 895c2438 }
		$sequence_2 = { 751a baea050000 33c9 41b84d4b4353 }
		$sequence_3 = { ff15???????? 488983f8000000 4883a3d800000000 33d2 488d8bb0000000 448d4220 e8???????? }
		$sequence_4 = { 83e21f 03c2 8bc8 83e01f c1f905 2bc2 488b5328 }
		$sequence_5 = { ff15???????? 488b0d???????? 48832700 33d2 4533c0 }
		$sequence_6 = { 83e27f 03c2 83e07f 2bc2 4863c8 8a8419c5010000 }
		$sequence_7 = { 83e3e0 41b84d4b4353 83c320 83e203 03c2 895910 c1f802 }
		$sequence_8 = { 88480d 8b5368 42 895368 }
		$sequence_9 = { 884c241b c744241c08000000 c783b401000001000000 ff93f0020000 }
		$sequence_10 = { 884c2450 83c9ff 33c0 f2ae }
		$sequence_11 = { 885004 33c0 f2ae f7d1 }
		$sequence_12 = { 88480d 8b4500 50 ff5018 }
		$sequence_13 = { 884805 8b0b b807000000 c6410600 8b4b04 3bc8 }
		$sequence_14 = { 88482b 81c6a1000000 8990b0000000 3bf2 }

	condition:
		7 of them and filesize <3475456
}
