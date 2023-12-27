rule win_buer_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.buer."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.buer"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { eb05 e8???????? 46 83fe20 7cd1 }
		$sequence_1 = { 8b00 8b4010 8945fc 61 }
		$sequence_2 = { 03c2 8b55e8 015158 8b55d8 894148 8b45dc 03c6 }
		$sequence_3 = { 03c1 8bcb 894144 8b45f0 03c2 8b55e8 }
		$sequence_4 = { c1e804 c1e104 0bc8 6a02 5b }
		$sequence_5 = { 57 60 64a130000000 8b400c 8b4014 8b00 8b4010 }
		$sequence_6 = { 83e003 83e800 7435 83e801 7420 83e801 }
		$sequence_7 = { 8365fc00 53 56 57 60 64a130000000 }
		$sequence_8 = { c7410c00000000 e9???????? 390424 0f8243010000 }
		$sequence_9 = { e8???????? 6a0c 68???????? 8d8424c0010000 50 8d842404010000 50 }
		$sequence_10 = { c7410c01000000 e9???????? 39c2 0f82d1000000 }
		$sequence_11 = { c3 8d442403 c644240301 b9???????? }
		$sequence_12 = { e8???????? 6a0c 6a00 50 e8???????? 85c0 7468 }
		$sequence_13 = { c1ee1a 03f8 8bc7 13ce }
		$sequence_14 = { e8???????? 6a0c 68???????? 8d8424e8000000 50 8d44245c 50 }
		$sequence_15 = { c1ee1a 037024 8bc6 c1e819 6bc813 }

	condition:
		7 of them and filesize <3031040
}