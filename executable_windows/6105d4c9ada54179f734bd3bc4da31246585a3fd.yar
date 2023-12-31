rule win_heloag_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.heloag."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.heloag"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 66ab aa 83c9ff 8bfe 33c0 }
		$sequence_1 = { 8bf7 8bfa 8a15???????? c1e902 f3a5 8bc8 }
		$sequence_2 = { 8d4dbc 51 ffd7 8b45c4 b919000000 }
		$sequence_3 = { 8b0d???????? 51 e8???????? 6a14 e8???????? 8bf0 83c408 }
		$sequence_4 = { f3a4 a2???????? a2???????? a3???????? }
		$sequence_5 = { 7cc4 8b45fc 8b0d???????? 40 }
		$sequence_6 = { 6a00 6a00 ffd0 33c9 a3???????? 85c0 0f95c1 }
		$sequence_7 = { 8d8dacfdffff 68???????? 51 e8???????? 8b55b4 83c41c 66c745b80200 }
		$sequence_8 = { 8b4e0c 3bcd 8b07 89442410 7464 }
		$sequence_9 = { 894b0c 8a48ff fec1 8848ff eb3c 6a01 55 }
		$sequence_10 = { 8b4108 50 e8???????? 6a01 }
		$sequence_11 = { 85c0 7505 a1???????? 8b4c242c }
		$sequence_12 = { 51 53 68???????? 8d4c2420 ff15???????? }
		$sequence_13 = { 8a442413 6a00 8bce 8806 ff15???????? }
		$sequence_14 = { 8b11 8bcf 52 6a00 50 ff15???????? }
		$sequence_15 = { a1???????? 894304 8b5608 895308 8b4e0c 894b0c }

	condition:
		7 of them and filesize <401408
}
