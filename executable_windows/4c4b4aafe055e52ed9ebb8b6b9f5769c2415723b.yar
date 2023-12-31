rule win_backbend_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.backbend."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.backbend"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 80a40500ffffff00 8d8500ffffff 56 50 ff15???????? }
		$sequence_1 = { 58 5f 5e c3 ff25???????? ff25???????? }
		$sequence_2 = { ffd6 ff7510 ffd3 8d8500feffff }
		$sequence_3 = { ff15???????? 85c0 7416 8d8500fbffff }
		$sequence_4 = { 56 e8???????? 8d8500fdffff 56 50 e8???????? 68???????? }
		$sequence_5 = { 90 90 90 bf???????? 57 e8???????? c70424???????? }
		$sequence_6 = { 8d8500f9ffff 50 e8???????? 8d8500f9ffff 50 e8???????? 83c424 }
		$sequence_7 = { ffd3 8d8500feffff 6800010000 50 ff15???????? 8d8500feffff 68???????? }
		$sequence_8 = { 56 ffd3 6a00 8d8500ffffff 56 50 ff15???????? }
		$sequence_9 = { 7416 8d8500fbffff 6a00 50 }

	condition:
		7 of them and filesize <49152
}
