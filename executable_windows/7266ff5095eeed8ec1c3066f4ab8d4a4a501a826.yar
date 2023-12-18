rule win_blackpos_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.blackpos."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackpos"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e9???????? b800000200 3bf8 7602 8bf8 8d85f4fffdff }
		$sequence_1 = { 3bca 7408 47 83ff44 72ef eb08 }
		$sequence_2 = { 83c414 85c0 7433 e8???????? 85c0 }
		$sequence_3 = { 8d4dbc 51 03c6 50 e8???????? }
		$sequence_4 = { 3bfb 0f84f8000000 68ff030000 8d85fdfbffff 53 50 }
		$sequence_5 = { f7f9 8b4dfc 5f 5e 5b 8bc2 }
		$sequence_6 = { 8b8040f84100 3bf0 7e44 83ee07 eb3f 2503000080 7905 }
		$sequence_7 = { 3bf7 7513 8d45e0 50 e8???????? 59 }
		$sequence_8 = { 6a07 59 6804010000 be???????? }
		$sequence_9 = { e8???????? 83c40c 85c0 7414 6a01 68???????? }

	condition:
		7 of them and filesize <3293184
}
