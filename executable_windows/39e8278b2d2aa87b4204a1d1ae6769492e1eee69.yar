rule win_finfisher_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.finfisher."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.finfisher"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 68???????? 6804010000 8d85ccf9ffff 50 }
		$sequence_1 = { 56 8d85ccf9ffff 50 e8???????? }
		$sequence_2 = { 0145d8 ebcd 897dd4 c745fcfeffffff }
		$sequence_3 = { 8b8590f7ffff 66c7005c00 8d85c0f7ffff 50 8d85dcfdffff 50 }
		$sequence_4 = { 0145d4 ebce 8975e4 eb07 }
		$sequence_5 = { 6a04 5f 8b85b4f7ffff 397804 740a bb230000c0 e9???????? }
		$sequence_6 = { 8d45ec 50 ffd6 8b7508 8d45fc }
		$sequence_7 = { 011a 8b55f0 83450802 49 }
		$sequence_8 = { 89bda0f7ffff 33db e9???????? 3daaaaaaaa }
		$sequence_9 = { 0145d8 ebcc 8975e4 eb07 }
		$sequence_10 = { 0108 83500400 a1???????? 8380780300003c 83fbfd }
		$sequence_11 = { 8985b0f7ffff bb020000c0 33f6 89b5a0f7ffff 89b5c0f7ffff }
		$sequence_12 = { 0118 8b45f0 83450802 4f }
		$sequence_13 = { 50 ffb5b4f7ffff ffb5c0f7ffff 33c0 397714 }

	condition:
		7 of them and filesize <262144
}
