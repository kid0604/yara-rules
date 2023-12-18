rule win_gazer_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.gazer."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gazer"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 85c0 7511 e8???????? 84c0 7508 }
		$sequence_1 = { 85c0 7511 e8???????? 84c0 7508 83c8ff e9???????? }
		$sequence_2 = { 85c0 7511 e8???????? 84c0 }
		$sequence_3 = { ff15???????? 85c0 7511 e8???????? 84c0 7508 83c8ff }
		$sequence_4 = { 7511 e8???????? 84c0 7508 83c8ff e9???????? }
		$sequence_5 = { ff15???????? 85c0 7511 e8???????? 84c0 7508 }
		$sequence_6 = { 7511 e8???????? 84c0 7508 83c8ff }
		$sequence_7 = { ff15???????? 85c0 7511 e8???????? 84c0 }
		$sequence_8 = { 85c0 7511 e8???????? 84c0 7508 83c8ff }
		$sequence_9 = { 4133c0 23c1 33c2 4103c1 }

	condition:
		7 of them and filesize <950272
}
