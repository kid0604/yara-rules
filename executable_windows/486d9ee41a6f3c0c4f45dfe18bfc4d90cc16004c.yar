rule win_medusa_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.medusa."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.medusa"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ae 085ffb cf 51 46 a8cf f8 }
		$sequence_1 = { 184e0f 6c 6f aa }
		$sequence_2 = { d8b8291ba3f9 a939ef568f 46 005f6e 69c7d0234b91 1c14 2a18 }
		$sequence_3 = { 51 ff7100 52 ff7200 53 }
		$sequence_4 = { 2048b3 a5 45 b051 9f }
		$sequence_5 = { 57 10872213d4b4 5b 00bb4b0c8cb2 }
		$sequence_6 = { ab 92 6f 0c48 b5f9 43 }
		$sequence_7 = { 5f e1fb 1cc9 3ca5 2c8e }
		$sequence_8 = { 670048ff 680049ff69 004aff 6a00 4b ff6b00 4c }
		$sequence_9 = { e60e 6c 7bbc 45 }
		$sequence_10 = { ff7300 54 ff740055 ff7500 56 }
		$sequence_11 = { 334a54 98 56 39ec 51 7fa1 6d }
		$sequence_12 = { b051 9f 4a d7 b9533e507c }
		$sequence_13 = { b5f5 42 317f52 56 }
		$sequence_14 = { bfdb4a7adc de6326 9e 45 334a54 98 }
		$sequence_15 = { 3ca5 2c8e a1???????? d528 32f4 }

	condition:
		7 of them and filesize <1720320
}
