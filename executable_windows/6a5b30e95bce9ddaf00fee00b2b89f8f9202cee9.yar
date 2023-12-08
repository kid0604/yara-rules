rule win_kpot_stealer_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.kpot_stealer."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kpot_stealer"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0bc1 0fb64f04 c1e208 0bca 0fb65707 c1e208 0bd6 }
		$sequence_1 = { 83f80f 7703 6a0f 58 3d00e00100 7605 83c8ff }
		$sequence_2 = { ff15???????? 85c0 7406 395df8 0f95c3 ff75fc ff15???????? }
		$sequence_3 = { 8b4508 6a00 56 e8???????? 8b5604 8b0e 8bc2 }
		$sequence_4 = { 89560c 6a10 5a 8bce e8???????? }
		$sequence_5 = { 8365f400 c745f039300000 c745fc00010000 57 }
		$sequence_6 = { 8bf2 81e600001000 0bce c1e914 81e300000600 8bf2 81e600e00100 }
		$sequence_7 = { 8bf0 7504 33c0 eb31 83feff 750a 8b4d08 }
		$sequence_8 = { 250f0f0f0f 33d0 c1e004 33c8 8bc2 }
		$sequence_9 = { c1e108 ff7514 0bc1 0fb64f02 ff7510 c1e110 }

	condition:
		7 of them and filesize <219136
}
