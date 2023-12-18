rule win_wastedlocker_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.wastedlocker."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wastedlocker"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 8bf0 ff7508 6a00 ff35???????? ff15???????? 5f }
		$sequence_1 = { 8945e4 8d45dc 50 c745dc18000000 897de0 }
		$sequence_2 = { 50 e8???????? 83c40c 56 8d85c8f1ffff 53 50 }
		$sequence_3 = { ffd3 8bf8 85ff 7419 6a20 57 ffd3 }
		$sequence_4 = { 8d45ec 50 8d45d4 50 6816011200 }
		$sequence_5 = { 3b45d0 0f8382000000 894dd8 394de0 740b 0fb703 034710 }
		$sequence_6 = { ff35???????? ff15???????? 5f ff75f8 ff15???????? }
		$sequence_7 = { 6a00 ff35???????? ff15???????? 8bd8 85db 7469 8b450c }
		$sequence_8 = { 2500f0ffff 56 0500100000 50 56 b812345607 }
		$sequence_9 = { bf04010000 ffd3 8bf0 85f6 746a 57 56 }

	condition:
		7 of them and filesize <147456
}
