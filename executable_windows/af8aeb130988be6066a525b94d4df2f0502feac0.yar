rule win_ramnit_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.ramnit."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ramnit"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 3a06 7512 47 46 e2f6 b801000000 59 }
		$sequence_1 = { 750b 4f 3b7d08 73e7 bf00000000 }
		$sequence_2 = { 57 56 fc 807d1401 }
		$sequence_3 = { 5f 59 5a 5b c9 c20800 55 }
		$sequence_4 = { ff750c ff75fc e8???????? 0bc0 7429 }
		$sequence_5 = { 8bc7 5a 5b 59 5f }
		$sequence_6 = { 8bc1 f7d0 48 59 5f 5e }
		$sequence_7 = { f3a4 fc 5e 5f 59 5a }
		$sequence_8 = { 8bd7 2b5508 59 5f 5e }
		$sequence_9 = { 8b5d0c 4b f7d3 23c3 }

	condition:
		7 of them and filesize <470016
}