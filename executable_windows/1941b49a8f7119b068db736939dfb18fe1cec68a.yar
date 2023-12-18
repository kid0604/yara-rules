rule win_ghost_rat_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.ghost_rat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ghost_rat"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6a01 56 ff15???????? 5e c20800 }
		$sequence_1 = { 8bd9 e8???????? 8b4d08 3bc8 }
		$sequence_2 = { 8b400c 85c0 7505 a1???????? 50 8bce }
		$sequence_3 = { 8be5 5d c20400 894df4 }
		$sequence_4 = { 894df4 c745f800000000 df6df4 83ec08 dc0d???????? }
		$sequence_5 = { 6a6b 8bce e8???????? 5f }
		$sequence_6 = { e8???????? 8b8e549f0000 83c41c 89848e14030000 8b86549f0000 }
		$sequence_7 = { 8d7b01 c60396 f3a5 53 8bcd }
		$sequence_8 = { 8db714030000 8b06 6aff 50 }
		$sequence_9 = { 8b5614 8b02 8b400c 85c0 }
		$sequence_10 = { e9???????? 8d45dc 50 681f000200 }
		$sequence_11 = { 50 ff15???????? ffb6a8000000 ff15???????? ffb6ac000000 }
		$sequence_12 = { 8dbd85feffff f3ab 66ab aa }
		$sequence_13 = { 6a00 6a00 c705????????20010000 e8???????? 8b35???????? }
		$sequence_14 = { e8???????? 8d85c0feffff 50 57 ff15???????? 8bf8 83ffff }
		$sequence_15 = { 83c40c 8d85b8feffff 50 8d85b4fdffff }
		$sequence_16 = { 8bce e8???????? 8b4df4 5f b001 5e }
		$sequence_17 = { 8bf0 83c40c 46 750b 5f 5e 33c0 }
		$sequence_18 = { ff15???????? 6a01 ff7620 ff15???????? 8b4e04 e8???????? }
		$sequence_19 = { ff7510 ff75dc ff15???????? 85c0 7507 c745e401000000 834dfcff }
		$sequence_20 = { 56 53 e8???????? 83c408 84c0 750b }
		$sequence_21 = { 68???????? 50 6802000080 e8???????? 83c41c 5f 5e }
		$sequence_22 = { 6a00 50 e8???????? 83c40c ff7508 6a40 ff15???????? }
		$sequence_23 = { 8365fc00 ff7508 ff15???????? 40 50 ff15???????? 59 }
		$sequence_24 = { 8b4608 8b7e20 8b36 813f6b006500 7406 }
		$sequence_25 = { c7014c696272 83e9fc c70161727941 83e9fc }
		$sequence_26 = { 813f6b006500 7406 813f4b004500 75e8 }
		$sequence_27 = { c7014c6f6164 83e9fc c7014c696272 83e9fc }
		$sequence_28 = { 7475 8b45bc 8b08 894db4 }
		$sequence_29 = { 8911 eb26 8b45b4 8b4d08 8d540102 }
		$sequence_30 = { 8b55dc 8b7a18 8b7220 0375f8 33c9 }
		$sequence_31 = { 6bc928 8b9538ffffff 8b8560ffffff 03440a0c 8985fcfeffff }

	condition:
		7 of them and filesize <357376
}
