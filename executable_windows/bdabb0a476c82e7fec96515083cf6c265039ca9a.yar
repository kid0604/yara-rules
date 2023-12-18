rule win_hawkball_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.hawkball."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hawkball"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83780c00 7506 33c0 8be5 }
		$sequence_1 = { 53 e8???????? 037dfc 83c40c 81ffffff0300 }
		$sequence_2 = { 0f84c6000000 6a04 8d442418 c744241860ea0000 50 6a06 57 }
		$sequence_3 = { 53 ff15???????? ff742414 8b35???????? ffd6 53 }
		$sequence_4 = { 85c9 746d 837dfc28 7d13 6b55fc05 69c2e8030000 }
		$sequence_5 = { 50 ff15???????? 897001 c600ff c7400500000000 }
		$sequence_6 = { b9???????? e8???????? a3???????? 833d????????00 740b 8b0d???????? }
		$sequence_7 = { 837dfc28 7d13 6b55fc05 69c2e8030000 50 }
		$sequence_8 = { 7405 8d4a10 eb47 b911000000 }
		$sequence_9 = { 8be5 5d c3 6a59 ff15???????? 85c0 }

	condition:
		7 of them and filesize <229376
}
