rule win_nemty_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.nemty."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nemty"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 5b c3 56 8bf0 3bf3 }
		$sequence_1 = { 68???????? e8???????? 8bc1 2bc7 83f801 }
		$sequence_2 = { 837dd810 8b75c4 8bc6 7305 8d45c4 8bf0 0fbe0418 }
		$sequence_3 = { e8???????? 6a01 33ff 8d7508 e8???????? 8b4dfc }
		$sequence_4 = { 68???????? e8???????? 59 84c0 7552 68???????? e8???????? }
		$sequence_5 = { ff15???????? 53 8d459c 50 ff35???????? }
		$sequence_6 = { 8bec 56 8bf0 8b4610 57 83f801 }
		$sequence_7 = { 8bec 8b4d0c 8b5510 3bca 740d 53 }
		$sequence_8 = { 7507 be???????? eb2b 83f802 7507 be???????? eb1f }
		$sequence_9 = { 8db524fdffff e8???????? 53 8db5ecfcffff e8???????? }

	condition:
		7 of them and filesize <204800
}
