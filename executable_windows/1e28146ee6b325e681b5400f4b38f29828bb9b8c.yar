rule win_rorschach_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.rorschach."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rorschach"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 33d2 488d8df8020000 e8???????? 88850e030000 b26e 488d8df8020000 e8???????? }
		$sequence_1 = { f65d7f 488d15ece30000 4c8d05e9e30000 488955df 488d05d2e30000 488955e7 488945bf }
		$sequence_2 = { f5 66d3f7 66c1f703 d3d7 4801e3 d2f0 c0f807 }
		$sequence_3 = { f30f7f4de0 660f6f05???????? f30f7f45f0 660f6f0d???????? f30f7f4d00 c74510771a771b c6451477 }
		$sequence_4 = { 0c40 8845df e8???????? 4c8d05e8180700 488d55c0 488d4da0 e8???????? }
		$sequence_5 = { 33c0 48894310 48c7431807000000 668903 488b4c2458 4833cc e8???????? }
		$sequence_6 = { 33d2 488d4da8 e8???????? 8845b4 b272 488d4da8 e8???????? }
		$sequence_7 = { e8???????? 88851e0b0000 b265 488d8de0080000 e8???????? 88851f0b0000 33d2 }
		$sequence_8 = { e8???????? c60000 ba0f000000 488d4d99 e8???????? c60000 488d4d99 }
		$sequence_9 = { f6d4 660fbec0 0f98c0 488d7f01 0fb6c0 0f94c4 88f0 }

	condition:
		7 of them and filesize <3921930
}
