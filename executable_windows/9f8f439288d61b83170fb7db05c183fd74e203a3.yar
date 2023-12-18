rule win_soundbite_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.soundbite."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.soundbite"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b5518 48 89451c 8b4a08 3bc8 7702 2bc1 }
		$sequence_1 = { c1e81f 8d4c02ff 398dd4fcffff 7d1f }
		$sequence_2 = { ff15???????? 8a4e02 8066030f 0fb7c0 240f 02c0 02c0 }
		$sequence_3 = { e8???????? 83c428 8d7de0 e8???????? 8b450c 8b4d18 8b5514 }
		$sequence_4 = { c745f0c4e9f2e5 c745f4e3f4eff2 66c745f8f900 894dc0 c745c4d3ffc8ff c745c8c5ffccff c745ccccffb3ff }
		$sequence_5 = { 49 894d18 3bc1 7437 8b7d14 8b5708 }
		$sequence_6 = { 8b4d08 8b550c 8d0411 83f802 }
		$sequence_7 = { 7702 2bc2 8b5104 8b3c82 8b4d2c 8b5528 51 }
		$sequence_8 = { 68???????? ff15???????? 8b7508 c7465ca0634200 83660800 33ff 47 }
		$sequence_9 = { 8d75a0 e8???????? 8b5da0 8b4da4 8bc3 2bc1 }

	condition:
		7 of them and filesize <409600
}
