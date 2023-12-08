rule win_confucius_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.confucius."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.confucius"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7434 3d91010000 7411 8a8f2a010000 84c9 7423 3d2c010000 }
		$sequence_1 = { 50 e9???????? 8bb424cc020000 6a00 85f6 0f95c1 41 }
		$sequence_2 = { 83c404 85c0 0f85c4feffff 8b7c2414 8b4c2420 0fbe01 83c0bb }
		$sequence_3 = { 83c444 8d442444 50 e8???????? 50 68???????? 8d4c2414 }
		$sequence_4 = { c1eb05 8945e4 2bf7 eb3e 8305????????ff 8315????????ff 781b }
		$sequence_5 = { 53 56 bf???????? e8???????? 83c408 85c0 7570 }
		$sequence_6 = { 2905???????? 1915???????? e9???????? 55 6800200000 56 57 }
		$sequence_7 = { 7409 8d45f4 50 e8???????? 807d0f00 740b 8d45e4 }
		$sequence_8 = { 51 e8???????? 68???????? c7874001000000000000 55 c6851885000001 e8???????? }
		$sequence_9 = { a2???????? 8a45d6 a2???????? 8a45d7 a2???????? 56 8d45d8 }
		$sequence_10 = { 6a01 ff10 8325????????00 e8???????? a1???????? 8b38 033d???????? }
		$sequence_11 = { 49 83f907 0f8685000000 8bfd 83c9ff f2ae f7d1 }
		$sequence_12 = { 3bc8 0f8500010000 8b866c850000 3bc2 0f85f2000000 6a05 56 }
		$sequence_13 = { 663b4548 1bdb 83e346 83c30b eb2a 3bfe 7509 }
		$sequence_14 = { 750c c705????????581b0000 eb15 33c0 384508 0f94c0 48 }
		$sequence_15 = { c20400 55 8bec 81ec08080000 53 33db 381d???????? }

	condition:
		7 of them and filesize <598016
}
