rule win_torrentlocker_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.torrentlocker."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.torrentlocker"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c3 83f801 7405 83f802 }
		$sequence_1 = { 8b0d???????? 5f c7000c000000 894804 }
		$sequence_2 = { 85c0 7514 e8???????? 3d00000600 }
		$sequence_3 = { 50 56 6a00 6a01 6a02 ff15???????? }
		$sequence_4 = { 8b0d???????? 890e e8???????? 8bd8 e8???????? 6a00 6a01 }
		$sequence_5 = { 83ec24 6a00 6a01 68???????? ff15???????? 85c0 7551 }
		$sequence_6 = { 56 ff15???????? 83f802 740f 83f803 740a }
		$sequence_7 = { e8???????? 3d00000600 1bc0 40 a3???????? eb05 }
		$sequence_8 = { 83c002 6685c9 75f5 2bc2 d1f8 8d440014 }
		$sequence_9 = { 52 50 ff15???????? 85c0 7519 8b0d???????? 51 }
		$sequence_10 = { 51 6a01 6a00 0d00800000 50 6a00 }
		$sequence_11 = { 8b0d???????? 5f 894e0c 5e }
		$sequence_12 = { 8b0d???????? 6a00 6a00 57 }
		$sequence_13 = { 48 85c0 7ff4 5f 33c0 5e c3 }
		$sequence_14 = { 8b0d???????? 57 6a00 51 ff15???????? 8bc6 }
		$sequence_15 = { c705????????00000000 e8???????? 8bf0 e8???????? }

	condition:
		7 of them and filesize <933888
}
