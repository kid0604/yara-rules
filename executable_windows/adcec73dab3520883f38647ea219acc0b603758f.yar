rule win_younglotus_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.younglotus."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.younglotus"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6802000080 e8???????? 83c41c 6a01 }
		$sequence_1 = { e8???????? 2b450c 50 8b4dfc }
		$sequence_2 = { 8b45e0 25ff000000 e9???????? c745e401000000 8b550c }
		$sequence_3 = { 50 ff15???????? 8b4dfc 8981a4000000 68???????? }
		$sequence_4 = { 50 8b4d0c 81e970010000 51 }
		$sequence_5 = { 83bda4faffff00 751b 68???????? 8d85a8faffff 50 ff15???????? 83c408 }
		$sequence_6 = { 6804010000 6a00 8d8da8faffff 51 6a01 6a00 }
		$sequence_7 = { 83c40c 8b45fc 83c00f 8945f8 6a03 }
		$sequence_8 = { 56 57 68???????? ff15???????? 8945dc 68???????? }
		$sequence_9 = { 50 ffd3 85c0 8945fc 0f84b7000000 }
		$sequence_10 = { 68???????? ffd6 ff7508 e8???????? 8bf8 59 85ff }
		$sequence_11 = { ff7508 50 e8???????? 8d430f }
		$sequence_12 = { 50 8945f4 ffd6 8d4df8 }
		$sequence_13 = { 6a01 53 ff15???????? 8b4de8 6a03 }
		$sequence_14 = { 8945e8 ffd6 68???????? 8945ec ffd7 68???????? }
		$sequence_15 = { ffd0 50 ff55f0 85c0 746f 8b450c }

	condition:
		7 of them and filesize <106496
}
