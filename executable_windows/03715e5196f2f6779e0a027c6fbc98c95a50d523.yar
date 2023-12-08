rule win_orangeade_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.orangeade."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.orangeade"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6800010000 8d4c2414 899c2488000000 e8???????? 50 53 }
		$sequence_1 = { 0f84c8000000 56 ff15???????? 8d4c2414 e8???????? 8b4c240c }
		$sequence_2 = { 8d4c2424 c684248828010002 e8???????? 8d4c2410 c684248828010001 e8???????? 8d4c2414 }
		$sequence_3 = { 8d4c240c 889c2420050000 e8???????? 8b8c2418050000 }
		$sequence_4 = { 50 b874280100 64892500000000 e8???????? 55 56 8d442408 }
		$sequence_5 = { c684248828010002 e8???????? 8d4c2410 c684248828010001 e8???????? }
		$sequence_6 = { 889c2414010000 f3ab 66ab aa b93f000000 }
		$sequence_7 = { 50 8d942470020000 51 52 ff15???????? b93f000000 }
		$sequence_8 = { f3ab 66ab aa 8d842414010000 6804010000 50 c784242805000001000000 }
		$sequence_9 = { 51 ffd6 68???????? 8d4c2410 }

	condition:
		7 of them and filesize <139264
}
