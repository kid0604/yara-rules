rule win_transbox_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.transbox."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.transbox"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 64a300000000 eb24 8b048d90b60110 41 50 890d???????? ff15???????? }
		$sequence_1 = { 33c9 83c414 85c0 0f9fc1 8bc1 8b4dfc 33cd }
		$sequence_2 = { 8d4e04 c706???????? 832100 83610400 51 50 ff15???????? }
		$sequence_3 = { e9???????? 55 8bec 56 8b7508 57 bf???????? }
		$sequence_4 = { f7fb 56 8bf0 bbe0077e00 8bc3 2bc6 83f801 }
		$sequence_5 = { f77dfc 50 51 e8???????? 83c40c 69c708020000 5f }
		$sequence_6 = { 8bbdbcd3ffff 53 6a01 8d8d28e1ffff 885dfc }
		$sequence_7 = { 8d85e8fdffff 6808020000 895dfc 53 50 89bddcfdffff 899de4fdffff }
		$sequence_8 = { 33c9 8985dcfcffff 51 50 }
		$sequence_9 = { 8d85f8faffff 50 e8???????? 8bd0 8b02 85c0 7402 }

	condition:
		7 of them and filesize <288768
}
