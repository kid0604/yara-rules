rule win_tofsee_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.tofsee."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tofsee"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8d8584feffff 50 68b7000000 68a9000000 6a0c 68???????? 68???????? }
		$sequence_1 = { f7f3 8b450c 8a0402 88043e 46 3b7508 7ce0 }
		$sequence_2 = { f7fb 80c261 881431 49 47 85c9 }
		$sequence_3 = { bf???????? 8b46fc 48 744d 48 743a }
		$sequence_4 = { 5e 5b c9 c3 56 57 ff15???????? }
		$sequence_5 = { 33c0 eb3a 8b4b3c 03cb 813950450000 75ef }
		$sequence_6 = { 0f8ee8f7ffff 5b 8b4570 83c004 50 ff15???????? ff7564 }
		$sequence_7 = { 8b4038 40 57 8bcb 8945fc e8???????? 8bc8 }
		$sequence_8 = { 55 56 57 8bf1 ffd3 8b3d???????? 8be8 }
		$sequence_9 = { c0e105 0ad9 32da 34c6 881e 46 3bf7 }

	condition:
		7 of them and filesize <147456
}