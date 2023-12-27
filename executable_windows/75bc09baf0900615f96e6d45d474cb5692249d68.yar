rule win_telb_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.telb."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.telb"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c744242400000000 e8???????? 68???????? ff15???????? a3???????? 8d4c2430 6a12 }
		$sequence_1 = { 68???????? 8d8c24a4000000 e8???????? 8d8c24a0000000 e8???????? 8d8c24a0000000 }
		$sequence_2 = { 668908 8d8d68eeffff c645fc26 e8???????? 8d8d68eeffff e8???????? 8d8dd0efffff }
		$sequence_3 = { 8945fc 85f6 7407 83feff 746f eb69 8b1c9d485c4100 }
		$sequence_4 = { 50 e8???????? 8b853ceeffff 83c40c 8985b0efffff 89b5b4efffff c645fc35 }
		$sequence_5 = { 8d85f0bfffff 50 ff15???????? 85c0 0f847b020000 6800200000 }
		$sequence_6 = { 0f8796150000 52 51 e8???????? 83c408 807c241200 }
		$sequence_7 = { 8d442468 50 e8???????? 837c244408 8d4c2430 }
		$sequence_8 = { 0f438570efffff 8d8d88efffff 50 e8???????? 6a01 68???????? 8d8d88efffff }
		$sequence_9 = { 85f6 0f8551010000 a1???????? b9???????? 83c0f5 50 56 }

	condition:
		7 of them and filesize <286720
}