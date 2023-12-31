rule win_screencap_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.screencap."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.screencap"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83c8ff e9???????? 4c8bfb 4c8be3 488d055eeb0000 49c1fc05 }
		$sequence_1 = { 2400 1000 00568b b424 }
		$sequence_2 = { 4c8bc0 8b5020 8b08 448d0c91 488b4c2458 33d2 e8???????? }
		$sequence_3 = { 488d1516630000 488d0def620000 e8???????? 85c0 755a 488d0d13200000 e8???????? }
		$sequence_4 = { 770a 488d4c2420 e8???????? 33c0 488b8c2430010000 4833cc e8???????? }
		$sequence_5 = { 488d1570c60000 e9???????? 488d1560c60000 e9???????? }
		$sequence_6 = { ff15???????? ff75e0 ff15???????? 682c384700 ff15???????? 8bf0 85f6 }
		$sequence_7 = { 48894c2408 4881ec88000000 488d0d9d220100 ff15???????? 488b05???????? 4889442458 4533c0 }
		$sequence_8 = { 48c1f905 4d6bc058 4d0384c940a30100 eb0a 4c8bc2 4c8d0d7d98ffff }
		$sequence_9 = { 488d0d099a0000 48891d???????? e8???????? 488d157a320100 488d4c2420 e8???????? }

	condition:
		7 of them and filesize <1391616
}
