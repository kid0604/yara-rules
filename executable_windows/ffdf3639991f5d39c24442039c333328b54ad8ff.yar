rule win_slingshot_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.slingshot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.slingshot"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 50 33db 53 ff15???????? 8bf0 3bf3 }
		$sequence_1 = { 6a08 59 8d7de8 e8???????? }
		$sequence_2 = { 85c9 0f8427020000 8d4b01 23c8 }
		$sequence_3 = { 89442438 8b4714 48 896c2430 89442428 48 }
		$sequence_4 = { b8736c6e67 e8???????? 4c 8be0 48 8bac24e8000000 }
		$sequence_5 = { 7526 68736c7d02 ff15???????? e8???????? 89442410 89542414 }
		$sequence_6 = { 8d4508 50 6a04 897d08 }
		$sequence_7 = { 59 e8???????? eb7f ff33 ff75f0 }
		$sequence_8 = { 3bcb 7504 6a08 eb7a }
		$sequence_9 = { 3bcb 7429 ff750c 51 ff15???????? }
		$sequence_10 = { 3bcb 743b 6afe 58 }
		$sequence_11 = { 48 8d4c2428 33ed 33d2 41 }
		$sequence_12 = { 48 8b5c2458 48 85db 7445 8b17 }
		$sequence_13 = { 2bd1 49 8d044c 45 8bcb 743a 4c }
		$sequence_14 = { 8bc8 44 8bc5 e8???????? }
		$sequence_15 = { 3bcb 7461 8b01 83f807 }
		$sequence_16 = { 3bcb 753c ff7708 eb28 }
		$sequence_17 = { 3bcb 7512 ff7708 ff37 }
		$sequence_18 = { 1bdb 83e323 03d9 eb96 8d4520 }
		$sequence_19 = { 8d843000040000 48 8905???????? e8???????? 48 }
		$sequence_20 = { e9???????? 49 3bfc 7434 48 }
		$sequence_21 = { 3bc3 7507 686c654000 ebca 391d???????? 7519 }
		$sequence_22 = { 3bcb 7442 395dfc 7414 }

	condition:
		7 of them and filesize <663552
}
