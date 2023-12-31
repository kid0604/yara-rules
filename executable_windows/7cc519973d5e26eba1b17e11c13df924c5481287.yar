rule win_darkpulsar_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.darkpulsar."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkpulsar"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff25???????? 33c0 40 c20c00 68???????? 64ff3500000000 }
		$sequence_1 = { c20c00 68???????? 64ff3500000000 8b442410 896c2410 8d6c2410 2be0 }
		$sequence_2 = { c21000 ff25???????? ff25???????? ff25???????? 33c0 }
		$sequence_3 = { 3a01 1bc0 83e0fe 40 5f }
		$sequence_4 = { 803f00 742e 47 ff450c 0fbe07 }
		$sequence_5 = { 56 8b35???????? 57 8b7d08 eb09 }
		$sequence_6 = { 59 59 3bd8 74e0 0fb607 }
		$sequence_7 = { 50 ffd6 8bd8 8b450c 0fbe00 50 ffd6 }
		$sequence_8 = { 56 e8???????? ff742414 50 e8???????? 83c410 }
		$sequence_9 = { 6a01 50 ff15???????? 8bf0 59 }
		$sequence_10 = { 83c410 83f8ff 0f95c1 49 8bc1 }
		$sequence_11 = { 53 33d2 56 57 33c0 }
		$sequence_12 = { ffd7 59 5f 5e c3 8b4c2404 85c9 }
		$sequence_13 = { 8d45cc 50 57 e8???????? 83c410 85c0 }
		$sequence_14 = { ffd6 59 59 8945f8 }
		$sequence_15 = { f7d8 59 1bc0 59 40 c3 e9???????? }
		$sequence_16 = { 8b5d10 56 8b7508 33d2 }
		$sequence_17 = { e8???????? ff7514 89460c e8???????? }
		$sequence_18 = { ff15???????? 8bf8 59 59 85ff 7502 }
		$sequence_19 = { 8bc1 c3 8b442404 85c0 7501 c3 }
		$sequence_20 = { 33c0 33d2 c3 8bff 55 8bec b863736de0 }
		$sequence_21 = { e8???????? 59 5e 83f8ff }
		$sequence_22 = { 59 5e 8b45fc c9 c3 }
		$sequence_23 = { 56 e8???????? 59 85c0 7625 }
		$sequence_24 = { e8???????? 8bf0 46 56 ff15???????? 59 }
		$sequence_25 = { 40 894588 83659800 85c0 }
		$sequence_26 = { 8903 894304 5f 8bc6 }
		$sequence_27 = { ff75f0 56 57 ff15???????? 83c40c }
		$sequence_28 = { 00db 7313 752f 3b742404 0f830b010000 }
		$sequence_29 = { 8945cc 8945d0 8b4608 6a05 50 885dec }
		$sequence_30 = { 66894df5 c745f702000000 e8???????? 83c408 }
		$sequence_31 = { 0fb606 50 ff15???????? 83c41c 85c0 }
		$sequence_32 = { 48 4e 897c2414 75eb 5f 8d4240 }
		$sequence_33 = { 668903 8b45e8 8930 33c0 ebdc ff742408 ff15???????? }
		$sequence_34 = { 00db 7309 75f4 8a1e 46 10db }
		$sequence_35 = { 00db 7313 75e1 3b742404 0f8318010000 }
		$sequence_36 = { 51 51 8b4508 8b4d0c 894dfc }
		$sequence_37 = { 0facf908 c1ef08 48 4e }
		$sequence_38 = { 8945e0 8945e4 8945d4 8945d8 8b450c 897de8 897ddc }
		$sequence_39 = { 8d8df9feffff 53 51 899d5ceeffff 899d60eeffff }
		$sequence_40 = { 8b4d08 8d7d0c 31c0 f3aa }
		$sequence_41 = { ffd3 ff7594 ff15???????? 83c414 837d9c00 741c 837d0c07 }
		$sequence_42 = { 33d7 c1ea10 5f 33d1 }
		$sequence_43 = { 8bec 8b4508 894508 d94508 5d }

	condition:
		7 of them and filesize <491520
}
