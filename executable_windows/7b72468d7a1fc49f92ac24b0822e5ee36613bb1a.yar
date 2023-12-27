rule win_goldbackdoor_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.goldbackdoor."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.goldbackdoor"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 6a20 89730c e8???????? 83c404 8945f0 8bc8 }
		$sequence_1 = { ff7608 ff15???????? 8b45ec 6aff ff7008 ff15???????? 8b45ec }
		$sequence_2 = { 6812010000 68???????? 6a6b 6a79 6a0a e8???????? }
		$sequence_3 = { ff15???????? 8d5508 8d4de0 e8???????? b9???????? 8bf0 e8???????? }
		$sequence_4 = { ff7614 e8???????? 83c404 83f840 7e07 68b1000000 ebbc }
		$sequence_5 = { ff7504 46 e8???????? 83c404 3bf0 7c9b 8b5c2418 }
		$sequence_6 = { ff761c e8???????? 83c408 85c0 74d4 e8???????? 50 }
		$sequence_7 = { ff742430 56 e8???????? 83c418 85c0 7417 8d442408 }
		$sequence_8 = { 0f8907ffffff 56 57 53 ff74244c e8???????? 33c9 }
		$sequence_9 = { 83f810 0f82e3020000 40 8d8d60ffffff 50 ffb560ffffff e9???????? }

	condition:
		7 of them and filesize <2455552
}