rule win_cryptolocker_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.cryptolocker."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cryptolocker"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7403 83cf01 8903 8bc7 5f 5e }
		$sequence_1 = { 740e 6a02 ffd6 8b55ec 8bf0 8b45f0 }
		$sequence_2 = { 741b 8b8664010000 85c0 7411 50 }
		$sequence_3 = { f6450c18 7468 8b5d0c 8b35???????? f6c310 }
		$sequence_4 = { 53 51 57 6a00 6a01 ff15???????? }
		$sequence_5 = { 8b86e0feffff 8d8ee0feffff 8b4024 ffd0 0fb6c0 5f 5e }
		$sequence_6 = { ff15???????? 8b4604 8b4004 ff743008 ff15???????? 5f 5e }
		$sequence_7 = { c70200000000 897a08 89420c 894a1c ff15???????? }
		$sequence_8 = { 0f8544010000 a0???????? 3c01 757a a1???????? 83f805 7539 }
		$sequence_9 = { 8901 8b45ec 894104 8b45f0 8906 8b45f4 894604 }

	condition:
		7 of them and filesize <778240
}
