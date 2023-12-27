rule win_downdelph_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.downdelph."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.downdelph"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 85c9 0f84d2feffff 53 56 57 89c3 }
		$sequence_1 = { 83c4f8 8bf2 33d2 8bdc }
		$sequence_2 = { e8???????? 48 50 8bc3 b901000000 8b15???????? }
		$sequence_3 = { 8d55d8 e8???????? 8b5708 88041a }
		$sequence_4 = { 53 56 33db 899de0fbffff }
		$sequence_5 = { 0f8cd6020000 46 33ff 8b15???????? 8bc7 e8???????? }
		$sequence_6 = { 8b45fc e8???????? 50 8b45f0 }
		$sequence_7 = { 2bd3 2bd7 8bfa 85ff 7d02 33ff }
		$sequence_8 = { 68???????? 64ff32 648922 6a00 6800000080 }
		$sequence_9 = { ff05???????? 7544 b8???????? e8???????? b8???????? }

	condition:
		7 of them and filesize <172032
}