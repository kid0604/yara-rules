rule win_wslink_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.wslink."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wslink"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 488bf0 4885c0 0f85ab000000 c7442420ec000000 4c8d0dcfbc0600 ba94000000 }
		$sequence_1 = { e9???????? 488d15beaf0700 41b804000000 488bce e8???????? 85c0 750c }
		$sequence_2 = { eb2a 8b4718 85c0 750b 488b4f08 e8???????? ffc8 }
		$sequence_3 = { 48894710 4885c0 7514 c744242085010000 4c8d0d88440a00 e9???????? 8b542460 }
		$sequence_4 = { e8???????? 85c0 0f848a000000 ffcf ffc3 85ff 7fd3 }
		$sequence_5 = { 830f04 be01000000 488bcd e8???????? 488bcd e8???????? 488b5c2450 }
		$sequence_6 = { e8???????? 85c0 0f84c9fdffff 8b8c2400010000 418bc4 85c9 0f94c0 }
		$sequence_7 = { ba70000000 4c8d0d82120a00 c744242067000000 8d4a94 448d42fa e8???????? 83c8ff }
		$sequence_8 = { e8???????? 85c0 0f8424feffff 488b03 4d8bcc 4d8bc7 498bd7 }
		$sequence_9 = { f70300010000 7407 e8???????? eb05 e8???????? 8b5718 33c9 }

	condition:
		7 of them and filesize <2007040
}
