rule win_koadic_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.koadic."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.koadic"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0f84b4020000 53 56 57 8b7c2424 bb01000000 83ffff }
		$sequence_1 = { 035c2408 53 58 e8???????? a3???????? 8b5c2414 035c2408 }
		$sequence_2 = { 83fb01 0f8da9000000 8b542404 ff35???????? e8???????? 8b15???????? }
		$sequence_3 = { 50 8d4c2420 51 e8???????? e9???????? 6a08 }
		$sequence_4 = { 3b1c24 7527 8b15???????? ff35???????? e8???????? 8d05c8334100 50 }
		$sequence_5 = { 72f1 eb07 8b34c5c4124100 8bc6 8d5001 }
		$sequence_6 = { 7507 c7450c02104100 53 56 8b7508 f6462c01 57 }
		$sequence_7 = { 50 68???????? ff35???????? e8???????? 21c0 7414 ff35???????? }
		$sequence_8 = { e8???????? 890424 6800000000 e8???????? a3???????? ff35???????? ff742404 }
		$sequence_9 = { ff15???????? 8b542434 81c200000800 89542428 eb04 8b5c2414 8b442434 }

	condition:
		7 of them and filesize <180224
}
