rule win_doubleback_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.doubleback."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.doubleback"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { b9e3050000 eb3b b90b070000 eb34 2d63450000 7428 }
		$sequence_1 = { b9ad060000 eb57 b9a7060000 eb50 b947060000 eb49 }
		$sequence_2 = { eb3b b90b070000 eb34 2d63450000 }
		$sequence_3 = { 3d39380000 741c 3dd73a0000 740e 3dab3f0000 }
		$sequence_4 = { b9e7050000 eb42 b9e3050000 eb3b b90b070000 }
		$sequence_5 = { b90b070000 eb34 2d63450000 7428 2d57020000 }
		$sequence_6 = { 774f 7446 3d00280000 7438 3d5a290000 742a 3d39380000 }
		$sequence_7 = { 7438 3d5a290000 742a 3d39380000 }
		$sequence_8 = { e8???????? 85c0 7508 c60703 e9???????? }
		$sequence_9 = { 7446 3d00280000 7438 3d5a290000 742a 3d39380000 741c }

	condition:
		7 of them and filesize <106496
}
