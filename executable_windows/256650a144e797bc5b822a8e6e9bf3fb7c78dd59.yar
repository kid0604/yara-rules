rule win_hardrain_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.hardrain."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hardrain"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 66c74424380000 f3ab 66ab b981000000 33c0 }
		$sequence_1 = { 51 56 89542414 8944241c e8???????? 83c410 85c0 }
		$sequence_2 = { 8b7c241c 6685ff 7509 5f 83c8ff 5e 83c410 }
		$sequence_3 = { ff15???????? 85c0 7eca 8d442430 }
		$sequence_4 = { 51 8bce e8???????? 85c0 7427 6a14 }
		$sequence_5 = { 68b4000000 52 50 e8???????? }
		$sequence_6 = { 8d842484000000 68???????? 50 e8???????? 8d8c248c000000 6800040000 8d942490040000 }
		$sequence_7 = { 83c418 c3 33c0 33c9 68b4000000 89442408 }
		$sequence_8 = { ff15???????? 8b0e 85c9 7406 8b11 6a01 ff12 }
		$sequence_9 = { 81ec0c010000 8b842414010000 8b942418010000 57 89442404 b942000000 }

	condition:
		7 of them and filesize <368640
}
