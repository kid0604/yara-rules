rule win_neddnloader_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.neddnloader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.neddnloader"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b450c 8908 ff15???????? 8bc7 5f }
		$sequence_1 = { c3 0fbcc0 8945f8 c1e803 2b45fc }
		$sequence_2 = { 8b5508 69c0b179379e c1e813 33c9 66890c42 }
		$sequence_3 = { 7506 83c102 83c202 3bcb }
		$sequence_4 = { 83c104 83c204 3bcf 72f0 8d43ff 3bc8 7311 }
		$sequence_5 = { 8bec 83e4f8 81ec10060000 a1???????? 33c4 8984240c060000 }
		$sequence_6 = { 3bc8 7311 0fb702 0fb731 663bc6 7506 }
		$sequence_7 = { 7501 41 8bc1 2b45fc 5f }
		$sequence_8 = { ff15???????? e8???????? 488d1576570000 488d0d4f570000 }
		$sequence_9 = { 4c8d4530 ba05000020 895d38 ff15???????? 85c0 749b }
		$sequence_10 = { c1e818 0fb6c8 8bc3 c1eb10 }
		$sequence_11 = { 4433a48180550100 400fb6c7 8bbd00020000 4433a48180590100 488d2d96d0ffff 4533650c 83ff0a }
		$sequence_12 = { c1e818 0fb6c8 410fb6c0 4133ac8e803c0100 4133ac8680480100 418bc0 }
		$sequence_13 = { 4133b48c804d0100 4133b48480590100 418bc0 41337510 c1e808 0fb6d0 418bc3 }
		$sequence_14 = { 4c8bd2 4c8bd9 48395a10 750a b801000000 }
		$sequence_15 = { 418bcd 41b981808080 4c8bde 412bcf 418bc1 4889742438 }

	condition:
		7 of them and filesize <3438592
}
