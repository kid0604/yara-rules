rule win_hardrain_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.hardrain."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hardrain"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 66a1???????? 53 56 57 50 e8???????? }
		$sequence_1 = { 50 56 ff15???????? 85c0 7e1e 8b54240c }
		$sequence_2 = { 6689442409 52 ff15???????? 8b4c2418 668944240b }
		$sequence_3 = { 8b842414010000 6a01 8d542408 680c010000 52 }
		$sequence_4 = { 6a00 51 53 89742430 c744242c01000000 c744242400000000 }
		$sequence_5 = { 8d4c2404 8d542414 89442410 51 }
		$sequence_6 = { 51 53 89742430 c744242c01000000 c744242400000000 c744242810270000 ff15???????? }
		$sequence_7 = { 8b44240c 85c0 765f 2bc3 }
		$sequence_8 = { 894c242c e8???????? 83c414 85c0 740a b802000000 5e }
		$sequence_9 = { 0f84c0000000 55 8bce e8???????? 85c0 0f84b0000000 55 }

	condition:
		7 of them and filesize <368640
}