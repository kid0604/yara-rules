rule win_ransoc_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.ransoc."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ransoc"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b573c 50 57 ffd2 ff4e3c 8b462c 8b4e3c }
		$sequence_1 = { 8bf0 8b5630 57 8d7e30 }
		$sequence_2 = { 894240 8b5040 895140 3bd7 741e }
		$sequence_3 = { 89703c 8b5134 895030 3bd7 7406 8b5134 }
		$sequence_4 = { 85c0 75f2 8b7140 85f6 758b 68???????? }
		$sequence_5 = { 740f 83f907 740a 83f906 }
		$sequence_6 = { 89462c a820 7406 8b4604 014804 8b462c a900080000 }
		$sequence_7 = { 895148 8b4830 85c9 7406 8b5034 895134 8b4834 }
		$sequence_8 = { 83c408 c3 6a00 6a01 55 }
		$sequence_9 = { 8b56e4 89542414 8d5c2410 891a 89442410 8b5004 8956e4 }

	condition:
		7 of them and filesize <958464
}