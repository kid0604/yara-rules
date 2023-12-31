rule win_miuref_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.miuref."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.miuref"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0f86ca000000 ff750c 8d45d0 ff7508 50 e8???????? 6a05 }
		$sequence_1 = { 767c c745fc02000000 837d080a 7369 0fb70473 6683f830 7225 }
		$sequence_2 = { ff15???????? 5e 5d c21000 55 8bec 81ec80000000 }
		$sequence_3 = { 7409 ff75e4 ff15???????? 8b45fc c9 c3 55 }
		$sequence_4 = { 8d8300010000 ff75fc 50 e8???????? 68???????? 8d45f8 50 }
		$sequence_5 = { 53 e8???????? 6a0a 68???????? 53 e8???????? ff756c }
		$sequence_6 = { 6a04 8d45f4 50 ff7610 57 e8???????? 83c410 }
		$sequence_7 = { 57 e8???????? 8b03 034510 ff750c 50 }
		$sequence_8 = { 56 57 33ff 85db 767f 8b7514 3bfb }
		$sequence_9 = { ff7578 8d4574 50 e8???????? 83c40c 8b4574 ff30 }

	condition:
		7 of them and filesize <180224
}
