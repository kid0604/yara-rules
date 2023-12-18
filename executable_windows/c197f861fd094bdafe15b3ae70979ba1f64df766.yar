rule win_wormhole_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.wormhole."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wormhole"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { eb1b 3d04000100 752a a1???????? 68???????? 6a06 }
		$sequence_1 = { 50 56 e8???????? 83c40c 8d4c2408 8d942414010000 }
		$sequence_2 = { ffd3 6a00 6a00 89442418 8d442428 }
		$sequence_3 = { e8???????? a1???????? 83c404 50 ff15???????? c705????????00000000 c705????????00000000 }
		$sequence_4 = { 75f0 a1???????? 85c0 74d5 e8???????? }
		$sequence_5 = { c705????????01000000 68f4010000 ff15???????? 8b15???????? 52 e8???????? }
		$sequence_6 = { 85f6 7512 6a04 68???????? 6a28 57 e8???????? }
		$sequence_7 = { 6a78 6a28 57 50 e8???????? }
		$sequence_8 = { 8b442404 56 57 8b7c2410 6a78 6a28 }
		$sequence_9 = { 7564 8b442418 3dff000000 7f59 6a0f }

	condition:
		7 of them and filesize <99576
}
