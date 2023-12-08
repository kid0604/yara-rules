rule win_poohmilk_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.poohmilk."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.poohmilk"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { d3eb 2bf1 8b0c850c344100 014c822c 40 89856cffffff e9???????? }
		$sequence_1 = { 898560f3ffff c705????????00000000 ffd7 8d8dccf7ffff 51 }
		$sequence_2 = { 0301 eb02 33c0 8b4d08 85c9 7406 }
		$sequence_3 = { 898d74d2ffff 898d78d2ffff 3bd9 7417 3bc1 7513 33c0 }
		$sequence_4 = { 83ffff 0f8410010000 53 8b1d???????? 6a02 }
		$sequence_5 = { 8bd6 e8???????? 33c9 3b85a4fdffff 5f }
		$sequence_6 = { 85c0 0f8499000000 68???????? 8d842424020000 50 ffd6 8b4c2410 }
		$sequence_7 = { 23fb d3eb 0fbe8a10344100 03f9 }
		$sequence_8 = { 5e c21000 8bff 55 8bec 8b4d0c }
		$sequence_9 = { 8b4710 8b4e28 53 52 8b5624 }

	condition:
		7 of them and filesize <245760
}
