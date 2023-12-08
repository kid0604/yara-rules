rule win_treasurehunter_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.treasurehunter."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.treasurehunter"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b4dfc 57 8901 e8???????? }
		$sequence_1 = { 84c9 75f9 2bf0 e8???????? 8bd0 }
		$sequence_2 = { 57 8955fc e8???????? 8bce }
		$sequence_3 = { 7e0b 4a e8???????? 0fafc6 5e }
		$sequence_4 = { 6a0c 8d85e0d6ffff 50 6800142d00 53 ff15???????? 85c0 }
		$sequence_5 = { 57 8bf9 8bca e8???????? 8b7508 }
		$sequence_6 = { 8bec 51 53 56 8b35???????? 8bd9 8b4d08 }
		$sequence_7 = { 7cf3 8b15???????? 8b0d???????? 6a07 }

	condition:
		7 of them and filesize <229376
}
