rule win_voidoor_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.voidoor."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.voidoor"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 83c410 83bfb40b000000 752e ff33 83bf500b000000 ffb608400000 }
		$sequence_1 = { c645fc10 e8???????? c78574feffff0f000000 c78570feffff00000000 c68560feffff00 8d9560feffff 8d8d78feffff }
		$sequence_2 = { 03f5 7458 803e2f 7509 83f804 7d04 40 }
		$sequence_3 = { 55 8bd8 ff15???????? 83c414 85db 0f85c3010000 8b542440 }
		$sequence_4 = { 8b742414 c744240800000000 83bec802000000 8b1e 57 8b834c010000 8dbe68050000 }
		$sequence_5 = { c60201 8b10 2bca 83f906 7d0a b801000000 5e }
		$sequence_6 = { 33c0 5f 59 c3 56 57 e8???????? }
		$sequence_7 = { b91b000000 5e 0f44d9 5d 8bc3 5b 83c408 }
		$sequence_8 = { e8???????? 83c40c 89442418 8983ac030000 68???????? 53 e8???????? }
		$sequence_9 = { c6434501 3944241c 7520 85f6 0f8565ffffff 837c243020 7337 }

	condition:
		7 of them and filesize <1744896
}
