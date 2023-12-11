rule win_atmitch_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.atmitch."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.atmitch"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 51 8bcc 89642404 68???????? ff15???????? }
		$sequence_1 = { 84c0 74db e8???????? 85c0 }
		$sequence_2 = { c744243000000000 e8???????? 8bf0 c7442420ffffffff 8b44240c }
		$sequence_3 = { eb1a 51 8bcc 89642410 68???????? ff15???????? e8???????? }
		$sequence_4 = { 8d4c241c ff15???????? 50 8d4c2418 c644244c06 }
		$sequence_5 = { 85c0 7408 8bc8 ff15???????? 8b4c2408 64890d00000000 }
		$sequence_6 = { 0faf6c2414 6a0e e8???????? 8bf8 }
		$sequence_7 = { 6a00 b9???????? e8???????? 8d4c240c ff15???????? }
		$sequence_8 = { 50 ff15???????? 56 51 8bcc }
		$sequence_9 = { 51 8bcc 89642414 68???????? 66a3???????? ff15???????? }

	condition:
		7 of them and filesize <73728
}
