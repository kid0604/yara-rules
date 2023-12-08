rule win_floki_bot_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.floki_bot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.floki_bot"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8945ec 8b460c e8???????? 8945f0 8b4610 }
		$sequence_1 = { 7408 33c0 66833b02 eb06 33c0 66833a02 8b4d10 }
		$sequence_2 = { 5f 8d4c09ff 23c1 c3 53 8b5c2408 }
		$sequence_3 = { 8d1448 8945fc 8955f4 3bc2 0f83bf000000 0fb708 83f920 }
		$sequence_4 = { 8d5df0 8a0c17 84c9 7403 880b }
		$sequence_5 = { 8b5508 66833c4a5c 7405 49 }
		$sequence_6 = { ff7708 e8???????? 84c0 745e e8???????? }
		$sequence_7 = { 8d04b0 833800 7421 8b00 803800 741a ff75f8 }
		$sequence_8 = { 53 56 68???????? 33db ff15???????? 8bf0 3bf3 }
		$sequence_9 = { 83f8ff 752f 8b7508 e8???????? 8bf0 3bf7 }

	condition:
		7 of them and filesize <286720
}
