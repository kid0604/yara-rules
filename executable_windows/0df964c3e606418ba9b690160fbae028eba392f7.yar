rule win_crypt0l0cker_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.crypt0l0cker."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crypt0l0cker"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 85c0 742b 57 50 6a00 ff35???????? ff15???????? }
		$sequence_1 = { 897dfc 8b15???????? 8b149514d1a800 8d8d44ffffff e8???????? 8d8d44ffffff }
		$sequence_2 = { 6a05 68152eeba0 6a19 e8???????? 8bc8 83c420 85c9 }
		$sequence_3 = { 5e c3 85ff b8???????? 0f45c7 50 e8???????? }
		$sequence_4 = { 5b 85ff 7e18 8b0e 83c1fc 03ca 8b01 }
		$sequence_5 = { 85f6 747c 83ec0c 8bd3 8bce ff75f0 e8???????? }
		$sequence_6 = { 33db 3b75f8 6a01 58 0f42d8 8b4508 895df8 }
		$sequence_7 = { 335d04 0fb6460a c1e208 0bd0 0fb6460b c1e208 0bd0 }
		$sequence_8 = { 5d c3 6a2c e8???????? 59 85c0 7501 }
		$sequence_9 = { 8bf8 85ff 7478 8bd6 8bcf e8???????? 8bcf }

	condition:
		7 of them and filesize <917504
}
