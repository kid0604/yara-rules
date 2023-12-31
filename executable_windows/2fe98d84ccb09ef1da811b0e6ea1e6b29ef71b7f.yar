rule win_hunter_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.hunter."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hunter"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0000 9c 35a035a435 a835 }
		$sequence_1 = { 0145f4 8d45b4 8b55f0 8b4de4 }
		$sequence_2 = { 01442428 59 11742428 85db }
		$sequence_3 = { 0145e8 8d838e000000 3bc2 8b45e8 }
		$sequence_4 = { 01442444 53 11542444 51 }
		$sequence_5 = { 0103 115304 e9???????? 8b4c241c }
		$sequence_6 = { 014140 89413c 899604010000 e9???????? }
		$sequence_7 = { 00443907 8a043a 88043b 8a443a01 }

	condition:
		7 of them and filesize <1056768
}
