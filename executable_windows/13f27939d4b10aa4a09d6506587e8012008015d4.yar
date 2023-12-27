rule win_mgbot_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.mgbot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mgbot"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6808020000 e8???????? 6804010000 8bf0 6a00 }
		$sequence_1 = { 6808020000 e8???????? 6804010000 8bf0 6a00 56 e8???????? }
		$sequence_2 = { 5b 8be5 5d c20800 6808020000 }
		$sequence_3 = { 6808020000 e8???????? 6804010000 8bf0 6a00 56 }
		$sequence_4 = { 8be5 5d c20800 6808020000 e8???????? }
		$sequence_5 = { 6808020000 e8???????? 6804010000 8bf0 }
		$sequence_6 = { 5d c20800 6808020000 e8???????? }
		$sequence_7 = { 8be5 5d c20800 6808020000 }
		$sequence_8 = { 5b 8be5 5d c20800 6808020000 e8???????? }
		$sequence_9 = { 0f8553ffffff 5f 33c0 5e }

	condition:
		7 of them and filesize <1677312
}