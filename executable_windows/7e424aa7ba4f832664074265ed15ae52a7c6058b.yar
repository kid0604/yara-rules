rule win_runningrat_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.runningrat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.runningrat"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 56 ff15???????? 8b8c2418010000 }
		$sequence_1 = { 8b4904 56 8b742410 56 8d542414 50 }
		$sequence_2 = { 85c0 7404 50 ff5650 8b5660 }
		$sequence_3 = { 8988100b0000 8d88740a0000 8988280b0000 33c9 c780180b000080cd0110 89901c0b0000 c780240b000098cd0110 }
		$sequence_4 = { 894554 89542428 b910000000 33c0 8d7c2438 }
		$sequence_5 = { 8d442440 c1e902 f3a5 8bca 50 83e103 }
		$sequence_6 = { 5d 33c0 5b 81c4f8020000 c20400 8b35???????? 6800000100 }
		$sequence_7 = { c7462400000000 83c610 6a00 56 ff15???????? 5e }
		$sequence_8 = { 7cd9 8bf2 8b8e80000000 b8cdcccccc f7a684000000 c1ea04 }
		$sequence_9 = { 83c404 395630 740d 8b542418 }
		$sequence_10 = { 8d942410010000 52 6a00 6a00 }
		$sequence_11 = { 8d842432020000 6a00 50 c684242c02000046 }
		$sequence_12 = { 83ea01 898c3c90000000 75ed 8bd3 33ff 8d4900 }
		$sequence_13 = { 8b742424 e9???????? 6803010000 8d442431 6a00 50 }
		$sequence_14 = { 33c0 e8???????? 81c468040000 c3 3b0d???????? 7502 }

	condition:
		7 of them and filesize <278528
}
