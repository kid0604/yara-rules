rule win_kasperagent_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.kasperagent."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kasperagent"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b442420 2b442418 8b4c2428 2bc7 40 99 2bc2 }
		$sequence_1 = { c3 e9???????? 6860020000 b8???????? e8???????? 8b4508 8b35???????? }
		$sequence_2 = { 3b5c2410 72c3 8b742414 8b7c241c 5d 5b 2bc1 }
		$sequence_3 = { 8b0f 8bc7 5f c6040e00 5e 5d 5b }
		$sequence_4 = { 750d 8b46f8 50 56 e8???????? 83c408 85c0 }
		$sequence_5 = { 8b4c2414 8b01 3b70f8 7fa9 }
		$sequence_6 = { e8???????? 8b4500 ff442414 b92d000000 66890c78 8d7c3f02 }
		$sequence_7 = { 668b28 668929 83c102 83c002 47 3bce }
		$sequence_8 = { ffd0 c645fc01 8b45d8 83c0f0 }
		$sequence_9 = { 2bc1 33d2 d1f8 2bf0 668911 8bce 781a }

	condition:
		7 of them and filesize <1605632
}
