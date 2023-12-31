rule win_dma_locker_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.dma_locker."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dma_locker"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 75f9 8b4e18 6a00 2bc2 50 57 }
		$sequence_1 = { 894c247c 8b4f0c 8d542418 52 8db42480000000 89842488000000 }
		$sequence_2 = { eb02 33f6 8dbc2494030000 c78424301d0000ffffffff e8???????? 6a04 56 }
		$sequence_3 = { 8b8c24b0060000 64890d00000000 59 5f 5e 5b 8b8c2498060000 }
		$sequence_4 = { e8???????? 83c404 8d8ddcfdffff 51 68???????? e8???????? }
		$sequence_5 = { 89471c 66894720 884722 8d44247c }
		$sequence_6 = { 83c404 6a00 51 8bf8 ff15???????? 8b15???????? }
		$sequence_7 = { ff15???????? 8b1d???????? 89442420 3b35???????? 7475 3b35???????? }
		$sequence_8 = { a3???????? ff15???????? 8b0d???????? 68???????? 51 ff15???????? 8b542414 }
		$sequence_9 = { e8???????? 0fbe4d08 51 8d95f4fdffff 68???????? }

	condition:
		7 of them and filesize <532480
}
