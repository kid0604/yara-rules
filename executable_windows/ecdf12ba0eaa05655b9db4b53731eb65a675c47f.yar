rule win_observer_stealer_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.observer_stealer."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.observer_stealer"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff742450 50 53 e8???????? ffd0 8d4c2410 e8???????? }
		$sequence_1 = { 8d4c245c e8???????? 68???????? 8d4c2474 e8???????? 837c243c10 8d7c2428 }
		$sequence_2 = { c20c00 51 51 53 55 8be9 b900010000 }
		$sequence_3 = { 83480804 c3 56 6a20 8bf1 e8???????? 59 }
		$sequence_4 = { dd01 83c474 85c0 0f84768d0000 b801000000 e9???????? 8b44240c }
		$sequence_5 = { 53 eb63 f684245404000001 7440 68???????? 8d842458030000 50 }
		$sequence_6 = { ff742410 ff742410 ff742410 e8???????? c20c00 51 51 }
		$sequence_7 = { 56 68???????? 50 ff7718 ffd3 83c414 8d4c2410 }
		$sequence_8 = { 8903 85c0 7409 5f 5e 5d 8bc3 }
		$sequence_9 = { 3bc1 7663 8bf7 6bc60c 50 e8???????? 6b6c24140c }

	condition:
		7 of them and filesize <614400
}
