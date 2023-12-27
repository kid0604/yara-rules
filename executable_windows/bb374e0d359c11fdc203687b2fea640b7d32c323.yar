rule win_medusa_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.medusa."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.medusa"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 680049ff69 004aff 6a00 4b ff6b00 4c ff6c004d }
		$sequence_1 = { 1a03 69c421f3ef6a 2048b3 a5 }
		$sequence_2 = { 52 ff7200 53 ff7300 54 }
		$sequence_3 = { 317f52 56 5c ab 92 6f 0c48 }
		$sequence_4 = { 9e 45 334a54 98 56 39ec 51 }
		$sequence_5 = { 9f c48b2addd977 7612 a5 ba3c533f71 }
		$sequence_6 = { e60e 6c 7bbc 45 }
		$sequence_7 = { 54 ff740055 ff7500 56 }
		$sequence_8 = { 99 5f 68066e570a 4f bfdb4a7adc }
		$sequence_9 = { 1ddf859f31 e476 0c48 ce 74ec 1b826a013061 }
		$sequence_10 = { 2a18 ae 085ffb cf }
		$sequence_11 = { b5f9 43 324dd5 1ddf859f31 e476 0c48 }
		$sequence_12 = { 5f e1fb 1cc9 3ca5 2c8e a1???????? d528 }
		$sequence_13 = { b051 9f 4a d7 b9533e507c }
		$sequence_14 = { 6c 6f aa 97 691c85470859bab566c1a5 }
		$sequence_15 = { 813bf80937dc 8b4c6386 8608 5f }

	condition:
		7 of them and filesize <1720320
}