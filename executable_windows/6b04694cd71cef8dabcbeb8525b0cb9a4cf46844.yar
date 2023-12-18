rule win_darkdew_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.darkdew."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkdew"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b55d0 c745b400000000 c745b80f000000 c645a400 83fa08 722e 8b4dbc }
		$sequence_1 = { 03c0 660f283485c0840110 baef7f0000 2bd1 }
		$sequence_2 = { 7202 8b12 8bca c745ac00000000 33c0 c745b007000000 }
		$sequence_3 = { 8d4d9c 8d45d4 c78586feffff00000000 0f434d9c ba14060000 }
		$sequence_4 = { c645fc11 8b55cc 83fa08 7232 8b4db8 8d145502000000 8bc1 }
		$sequence_5 = { 6a00 ff15???????? cc 55 8bec 64a100000000 6aff }
		$sequence_6 = { b991000000 8dbc2470020000 8bf3 f3a5 8bf0 8dbc24b4040000 8d842480030000 }
		$sequence_7 = { e8???????? 8bf8 c645fc19 8d55d4 837de810 }
		$sequence_8 = { 85c0 0f8488000000 8b4df8 8d5823 8b55fc }
		$sequence_9 = { 8db3d0feffff 8bce 83e210 8d7901 0f1f4000 }

	condition:
		7 of them and filesize <279552
}
