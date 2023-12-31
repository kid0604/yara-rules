rule win_taidoor_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.taidoor."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.taidoor"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7cf5 c745fcfcffffff 33ff 33db }
		$sequence_1 = { f775fc 8bf2 8d04f6 ffb485f4b7ffff ff15???????? 85c0 }
		$sequence_2 = { 59 8d85a0fdffff 59 50 e8???????? }
		$sequence_3 = { 57 a0???????? c745fc01000000 8ac8 f6d9 1bc9 33db }
		$sequence_4 = { 66ab aa 895dfc ffd6 40 85c0 7e29 }
		$sequence_5 = { b940420f00 f7f9 8d45e0 52 ff35???????? ff35???????? }
		$sequence_6 = { ff75f0 ffd6 8d4d08 885dfc e8???????? 834dfcff 8d4d10 }
		$sequence_7 = { ff75ec 8d4df0 e8???????? 8b450c 46 3b70f8 7cdc }
		$sequence_8 = { e8???????? ff75ec 8d85a0fdffff 50 51 8bcc 8965f4 }
		$sequence_9 = { bf80020000 57 c745fc01000000 ffd3 8bf0 }

	condition:
		7 of them and filesize <49152
}
