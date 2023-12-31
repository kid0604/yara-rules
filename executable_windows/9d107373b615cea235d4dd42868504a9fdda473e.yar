rule win_ascentloader_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.ascentloader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ascentloader"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 1bc0 f7d8 eb02 8bc3 85c0 }
		$sequence_1 = { 741b 6a1a 2bf7 59 }
		$sequence_2 = { 85c0 7414 8b0f e8???????? 8b4e48 e8???????? 33c0 }
		$sequence_3 = { 40 001c5b 40 0023 }
		$sequence_4 = { c78564ffffff76650d0a 66c78568ffffff0d0a c6856affffff00 f30f7f856cffffff 660f6f05???????? f30f7f857cffffff }
		$sequence_5 = { 6a01 58 0f43f0 6a22 59 }
		$sequence_6 = { 40 0038 aa 40 }
		$sequence_7 = { 83f8ff 7518 ff15???????? 57 ff15???????? ff15???????? e9???????? }
		$sequence_8 = { 85c0 7508 6a11 e8???????? 59 ff34f5c8484100 }
		$sequence_9 = { 8d45e0 50 56 ff15???????? 8b5dec }

	condition:
		7 of them and filesize <253952
}
