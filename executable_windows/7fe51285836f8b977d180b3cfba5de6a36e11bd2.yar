rule win_keylogger_apt3_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.keylogger_apt3."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.keylogger_apt3"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8be8 8d442458 50 55 57 }
		$sequence_1 = { 3bf3 7523 68???????? ff15???????? 5f }
		$sequence_2 = { 8b35???????? 8d6b08 55 50 ffd6 }
		$sequence_3 = { 7453 53 8b5c240c 55 56 8b35???????? 8d6b08 }
		$sequence_4 = { 89442420 3bf8 7216 5b 5f }
		$sequence_5 = { ffd6 50 ffd7 ffd3 89442420 83f8ff 7551 }
		$sequence_6 = { 0fb69695010000 50 0fb68694010000 51 52 50 }
		$sequence_7 = { 84c0 75f8 2be9 8d5501 52 }
		$sequence_8 = { e8???????? 68???????? 68???????? 8d4d7c e8???????? 8b45dc }
		$sequence_9 = { c7442434d8174300 ffd6 8d542404 52 89442434 }

	condition:
		7 of them and filesize <761856
}