rule win_nighthawk_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.nighthawk."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nighthawk"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8983a8000000 4c397d0f 720f 488b4df7 4885c9 7406 e8???????? }
		$sequence_1 = { ff15???????? 48897b48 48837b3808 720e 488b4b20 4885c9 7405 }
		$sequence_2 = { 740d 0f104030 448d7701 0f11442420 498d4f30 ff15???????? 4585f6 }
		$sequence_3 = { 4c8bd2 488d354b95f5ff 4183e20f 488bfa 492bfa 488bda 4c8bc1 }
		$sequence_4 = { 7419 e8???????? 488b5310 41b801000000 488bc8 e8???????? eba5 }
		$sequence_5 = { ff15???????? 85c0 0f844a040000 448b4510 4c897588 4c897598 458d7e0f }
		$sequence_6 = { 8b02 418901 890a e9???????? 418b08 418b03 418900 }
		$sequence_7 = { 4903ca 4b890c01 eb34 6683f803 7509 4923ce 46011401 }
		$sequence_8 = { 488d542470 488d4d20 e8???????? 488bd0 488d4d40 e8???????? 90 }
		$sequence_9 = { 4c894c2448 4c89642440 4c89642438 4489642430 48894c2428 4889442420 4533c9 }

	condition:
		7 of them and filesize <1949696
}
