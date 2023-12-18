rule win_iconic_stealer_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.iconic_stealer."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.iconic_stealer"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e9???????? 4c8b13 4c8d05e6c60300 488bc6 488bce 83e03f 48c1f906 }
		$sequence_1 = { eb29 488d0c76 8d4601 898790000000 488b8788000000 c704c876000000 8954c804 }
		$sequence_2 = { 894338 66897318 66894b3e 6644896316 6644894b3c 663bf1 0f85dc000000 }
		$sequence_3 = { e8???????? 4881c430020000 415f 415d 415c 5f 5e }
		$sequence_4 = { 5f 5e 5d c3 40f6c504 7419 4c8bc7 }
		$sequence_5 = { eb05 b901000000 894f28 4885db 741f 8b4f28 48895f10 }
		$sequence_6 = { f2490f2ad5 488d4dc7 f20f5e15???????? 66490f7ed0 e8???????? e9???????? 448b44242c }
		$sequence_7 = { ffc7 4883c108 3bfa 7cf1 e9???????? 488b4b20 4885c9 }
		$sequence_8 = { e9???????? 488b75a8 4c8b442470 8b06 83c003 413b00 7e1f }
		$sequence_9 = { c7430400000000 41ba1f000000 49bb1142082184104208 418b49f8 85c9 745b 8d4701 }

	condition:
		7 of them and filesize <2401280
}
