rule win_breakthrough_loader_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.breakthrough_loader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.breakthrough_loader"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 57 8bb050764400 8bce ff15???????? ffd6 59 8b8d30fdffff }
		$sequence_1 = { 83c408 8b45fc 85c0 742d }
		$sequence_2 = { 8b8640354500 85c0 740e 50 e8???????? 83a64035450000 59 }
		$sequence_3 = { 660f1f440000 8a01 41 84c0 75f9 2bcb 8d45cc }
		$sequence_4 = { 7542 0c80 88441628 8b04bd40354500 c644102901 eb2e 0c80 }
		$sequence_5 = { 8d44240c 8b4b38 8d7c2410 0f437c2410 8d742410 }
		$sequence_6 = { 83f9ff 750b 33c0 5f 5e }
		$sequence_7 = { c6471000 c7473c07000000 c7473800000000 66894728 }
		$sequence_8 = { 0c80 88441628 8b0cbd40354500 c644112900 837dfc00 }
		$sequence_9 = { 0f826d9f0000 0faf4d0c 807d1000 7431 81f900100000 }

	condition:
		7 of them and filesize <753664
}