rule win_icedid_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.icedid."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.icedid"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 85c0 7420 837c241000 7419 }
		$sequence_1 = { 6803800000 ff75f8 ff15???????? 8bf0 85f6 }
		$sequence_2 = { 50 ff15???????? 8bf7 8bc6 }
		$sequence_3 = { ff36 6a08 ff15???????? 50 ff15???????? eb0f }
		$sequence_4 = { ff15???????? 85c0 7511 56 57 ff15???????? }
		$sequence_5 = { 803e00 7427 6a3b 56 ff15???????? 8bf8 }
		$sequence_6 = { 833e00 50 7413 ff36 6a08 ff15???????? }
		$sequence_7 = { 50 ff15???????? 33c0 40 eb11 }
		$sequence_8 = { 8bf0 8d45fc 50 ff75fc 6a05 }
		$sequence_9 = { 8d5808 0fb713 8954241c 66c16c241c0c 0fb7d2 }
		$sequence_10 = { 83c414 47 3b7820 72d1 }
		$sequence_11 = { 33ff 397820 7633 53 8bdf }
		$sequence_12 = { eb5c 8d5004 89542414 8b12 }
		$sequence_13 = { 0132 47 83c302 3bfd 72c4 8b542414 0302 }
		$sequence_14 = { 5f 743f 8d5808 0fb713 }
		$sequence_15 = { 3b7820 72d1 5b 33c0 40 5f }
		$sequence_16 = { ff15???????? 85c0 750a b8010000c0 e9???????? }
		$sequence_17 = { 8a4173 a808 75f5 a804 }
		$sequence_18 = { ff5010 85c0 7407 33c0 }
		$sequence_19 = { 41 8be9 49 8900 48 85c9 }
		$sequence_20 = { 48 8bd3 48 8bcf ff15???????? f644242080 }
		$sequence_21 = { eb21 41 0fb6c1 41 8d4960 }
		$sequence_22 = { 0fb74b02 8945e4 41 0fb7c6 0fafc8 0fb705???????? }
		$sequence_23 = { 85c9 7418 48 8b5320 4c 8d04c8 }
		$sequence_24 = { ba00000080 ff15???????? 488bf0 4883f8ff 7507 }
		$sequence_25 = { 740f 488d15674c0000 ff15???????? eb0d 488d15804c0000 ff15???????? 488bd5 }
		$sequence_26 = { 488b742438 4883c420 5f c3 488bc4 53 }
		$sequence_27 = { 4883ff04 0f8210010000 4883ef04 48897c2430 4885db 753d }
		$sequence_28 = { 4c8d8598020000 488d9590020000 488d4d56 e8???????? 85c0 750b }
		$sequence_29 = { 0f845affffff 488bcd ffd0 488b5c2438 }
		$sequence_30 = { ff15???????? 488d5702 488bce ff15???????? ba22000000 488bce ff15???????? }
		$sequence_31 = { ff15???????? 89842468010000 ff15???????? 448bc0 488d4c2440 8b842468010000 488d15e04e0000 }
		$sequence_32 = { 488bd6 488d0c5f e8???????? 4803d8 488d0c5f e8???????? 4803d8 }
		$sequence_33 = { 4885ff 746b 410fb6c3 8bd0 }
		$sequence_34 = { 488bf0 4885c0 750d ff15???????? 33c0 e9???????? }
		$sequence_35 = { 4863c8 488d15883b0000 4803d9 488d0c5f ff15???????? }
		$sequence_36 = { 4c8d05d9370000 0fb6c8 48ffc2 8bc1 83e10f 48c1e804 420fbe0400 }
		$sequence_37 = { 33db 215c2430 4885ff 7525 488d0dd5370000 }
		$sequence_38 = { ff15???????? 448b4c2428 4c8d057e3a0000 4863c8 488d15883b0000 }
		$sequence_39 = { ff15???????? e9???????? 488bb590020000 488bbd98020000 488bde }

	condition:
		7 of them and filesize <303104
}
