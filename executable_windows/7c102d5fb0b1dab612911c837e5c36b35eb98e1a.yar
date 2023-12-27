rule win_crypt0l0cker_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.crypt0l0cker."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crypt0l0cker"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 85c0 0f8486000000 53 8d58ff c1eb02 56 }
		$sequence_1 = { 8b4640 85c0 0f8479000000 83780c00 7473 6800010000 e8???????? }
		$sequence_2 = { 85f6 0f8ead000000 8d4108 8d04b8 894508 8b4510 83c008 }
		$sequence_3 = { 55 56 8d44240f 8bea 50 6a01 ff35???????? }
		$sequence_4 = { 83c40c 33c0 6689043b 897e08 85ff 0f84d6000000 }
		$sequence_5 = { 8b4c243c 8b442430 8911 894104 eb17 8bcf e8???????? }
		$sequence_6 = { b9???????? 3d90010000 0f4cce 8bf1 8b7f04 85f6 74c9 }
		$sequence_7 = { 8bce e8???????? 8bf8 83c408 85ff 7438 83c705 }
		$sequence_8 = { 68???????? 6a05 6840b6b9a6 6a1c e8???????? 83c424 }
		$sequence_9 = { 0f8581020000 807dee81 0f8577020000 ff75ef ff15???????? 8b0f 8bd3 }

	condition:
		7 of them and filesize <917504
}