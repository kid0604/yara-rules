rule win_dmsniff_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.dmsniff."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dmsniff"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 52 e8???????? 83c410 3dffff0000 0f85a8030000 }
		$sequence_1 = { ff7510 ff75fc e8???????? 89c7 ff75fc ff15???????? }
		$sequence_2 = { 09ff 7413 81fe19000200 7507 be19010200 ebd9 31c0 }
		$sequence_3 = { e9???????? 8b45ec 0145dc e9???????? ff75d4 ff15???????? }
		$sequence_4 = { 83ffff 7504 31c0 eb32 6a00 }
		$sequence_5 = { 0f855d060000 68???????? e8???????? 6a01 }
		$sequence_6 = { 52 e8???????? 83c410 3dffff0000 0f8522020000 68???????? e8???????? }
		$sequence_7 = { c745d000001000 8d45fc 50 ff75d0 ff35???????? }
		$sequence_8 = { 57 ff15???????? 89c6 56 6a00 68ff0f1f00 ff15???????? }
		$sequence_9 = { e8???????? 83c410 3dffff0000 0f85cf030000 68???????? e8???????? 6a01 }

	condition:
		7 of them and filesize <131072
}
