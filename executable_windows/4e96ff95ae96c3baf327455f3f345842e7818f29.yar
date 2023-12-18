rule win_unidentified_042_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.unidentified_042."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_042"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 85c0 754f 6a02 53 56 8d8d9cfeffff 57 }
		$sequence_1 = { 56 8d8d68e1ffff 51 8d9554f7ffff 52 89b550f7ffff }
		$sequence_2 = { 5b 85c0 78dd 8b45fc 8b55f8 0fb64c3801 4a }
		$sequence_3 = { 8b4db8 895640 8b9518fdffff 895620 8b9520fdffff 894e44 8b8d1cfdffff }
		$sequence_4 = { 8d8580cbffff 50 6a00 ff15???????? 85c0 7527 8b1d???????? }
		$sequence_5 = { 5e 8bc7 5f 5d c3 8b7514 85f6 }
		$sequence_6 = { 8bc3 2bc2 8d0c91 2bf0 42 8d3c87 3bf2 }
		$sequence_7 = { 85db 0f85af000000 8d45ac 8bf0 8d5d9c 50 }
		$sequence_8 = { 8d4df8 51 8d5df4 e8???????? 83c408 85c0 780d }
		$sequence_9 = { 52 50 8d4b70 e8???????? 83c408 85c0 0f850b020000 }

	condition:
		7 of them and filesize <516096
}
