rule win_webc2_greencat_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.webc2_greencat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_greencat"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 57 50 e8???????? 59 8bd8 59 eb03 }
		$sequence_1 = { 59 59 e9???????? ff35???????? ff15???????? 3bc6 }
		$sequence_2 = { 33f6 895df4 8d450c 50 ff35???????? ff15???????? 817d0c03010000 }
		$sequence_3 = { 395ddc 752d 391d???????? 7525 3bf3 7521 }
		$sequence_4 = { e8???????? 83c418 53 6a02 }
		$sequence_5 = { 8d85fcfeffff 33ff 6804010000 50 }
		$sequence_6 = { 50 53 ff15???????? 33c9 8945f0 }
		$sequence_7 = { 8bf0 395ddc 752d 391d???????? 7525 3bf3 7521 }
		$sequence_8 = { ff75fc ff15???????? 83c428 53 6880000000 }
		$sequence_9 = { 0fbe4007 83e830 8945f8 8d85f8fdffff 50 }

	condition:
		7 of them and filesize <57344
}
