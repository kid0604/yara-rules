rule win_lookback_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.lookback."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lookback"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 74c5 83f8ff 0f8427010000 8b0d???????? 8d442418 50 51 }
		$sequence_1 = { 8b7c241c 33ed 8b473c 8b443878 03c7 8b5024 }
		$sequence_2 = { 55 8bec 51 53 c745fc00000000 b801000000 }
		$sequence_3 = { 8a442413 893d???????? 3c01 893d???????? 893d???????? 752e 33db }
		$sequence_4 = { 8bc8 6a01 83e103 6a02 f3a4 ff15???????? }
		$sequence_5 = { 5d 5b 59 c3 0594010000 8b08 894d00 }
		$sequence_6 = { 7477 a1???????? 50 ff15???????? }
		$sequence_7 = { 03f7 833e00 742d 8bc6 }
		$sequence_8 = { 8b4df8 c1e010 5f 5e 0bc1 }
		$sequence_9 = { 50 52 ff542420 85c0 751b a1???????? 50 }

	condition:
		7 of them and filesize <131072
}