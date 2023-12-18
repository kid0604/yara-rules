rule win_xfsadm_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.xfsadm."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xfsadm"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83c40c 85c0 0f8431010000 81ff???????? 0f849f000000 6a01 68???????? }
		$sequence_1 = { 50 ff15???????? ffb534fdffff 8bf0 ff15???????? 0fb60d???????? 33c0 }
		$sequence_2 = { 8b7e38 85ff 0f8576010000 53 68f80f0000 e8???????? }
		$sequence_3 = { 85c9 7455 83c60c 3bf1 744e }
		$sequence_4 = { 8b4008 8a0406 3c3d 745e }
		$sequence_5 = { 83fa02 7211 8b4dfc 8a06 46 8b0c8df8d84200 88440f2b }
		$sequence_6 = { 5b 8be5 5d c20800 3c2f 751c }
		$sequence_7 = { 2d10010000 741d 83e801 7521 0fb74510 83f801 }
		$sequence_8 = { 8d460c 83c410 3bc8 7409 51 e8???????? 83c404 }
		$sequence_9 = { 50 e8???????? 8b4e08 8d460c 83c410 3bc8 }

	condition:
		7 of them and filesize <566272
}
