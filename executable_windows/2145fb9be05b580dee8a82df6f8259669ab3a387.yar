rule win_smarteyes_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.smarteyes."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.smarteyes"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 51 8d85d4fdffff 50 e8???????? 8d85d4fdffff 889c35d4fdffff 83c40c }
		$sequence_1 = { 68???????? e9???????? 53 68???????? e8???????? 33c0 40 }
		$sequence_2 = { 3bc3 0f8426030000 8d842488040000 50 6804010000 ff15???????? 85c0 }
		$sequence_3 = { 7478 83c00c 8bc8 8d7901 8a11 41 84d2 }
		$sequence_4 = { 7413 8d85ecfeffff 57 50 }
		$sequence_5 = { ff742424 ff742420 ff15???????? 85c0 7547 }
		$sequence_6 = { e8???????? 59 59 8d8548f5ffff 50 8d9d78f7ffff e8???????? }
		$sequence_7 = { 7514 8bf9 c744241001000000 e8???????? e9???????? 68???????? 8d442424 }
		$sequence_8 = { 8d45ff 50 e8???????? 8a4736 8845ff 53 8d45ff }
		$sequence_9 = { 8bd6 0fb7c0 6683f82f 7406 6683f85c 7502 8bca }

	condition:
		7 of them and filesize <429056
}
