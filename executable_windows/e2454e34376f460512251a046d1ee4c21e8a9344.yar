rule win_dubrute_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.dubrute."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dubrute"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 56 57 33db 6aff 68???????? 895dfc ff15???????? }
		$sequence_1 = { 8d4fff 3bf1 7322 8a06 84c0 740f 3cff }
		$sequence_2 = { 42 46 8801 8a45fd 884101 8a45fe 884102 }
		$sequence_3 = { c60008 ff06 8b06 802000 ff06 8b06 c60003 }
		$sequence_4 = { 8d848148040000 c745fc01000000 8945e8 8b4514 1bdb 83e308 85c0 }
		$sequence_5 = { ff771c ff7714 e8???????? 83c410 85c0 7420 ff36 }
		$sequence_6 = { 3bd8 7302 8bc3 8d4df8 51 50 ff7514 }
		$sequence_7 = { 50 e8???????? 8b45f8 03c3 0106 8a4df4 8b06 }
		$sequence_8 = { e8???????? 59 50 8d4e40 ff75d8 ff15???????? 8b8ee0000000 }
		$sequence_9 = { 8bf8 59 85ff 59 0f8ce3000000 6a10 ff7518 }

	condition:
		7 of them and filesize <598016
}
