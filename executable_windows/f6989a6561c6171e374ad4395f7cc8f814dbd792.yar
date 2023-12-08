rule win_ironhalo_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.ironhalo."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ironhalo"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 8b3d???????? 68e0930400 85c0 7573 }
		$sequence_1 = { 89542410 89542414 52 668954241c }
		$sequence_2 = { 68???????? 51 68???????? 55 ff15???????? 8bd8 85db }
		$sequence_3 = { 8d3c8d60e04000 c1e603 8b0f 80650b48 }
		$sequence_4 = { 7352 8bc8 8bf0 c1f905 83e61f 8d3c8d60e04000 c1e603 }
		$sequence_5 = { 8d442410 56 50 c744241844000000 }
		$sequence_6 = { c3 ffd7 8d542438 8d442410 52 50 e8???????? }
		$sequence_7 = { 33c9 33ed 8a06 57 84c0 }
		$sequence_8 = { 2bd1 8d34b5f8c14000 832600 83c60c 4a 75f7 }
		$sequence_9 = { 56 50 8d8c2438030000 6a01 51 e8???????? 8b44242c }

	condition:
		7 of them and filesize <131072
}
