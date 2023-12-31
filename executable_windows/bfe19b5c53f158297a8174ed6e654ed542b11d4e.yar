rule win_xtunnel_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.xtunnel."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xtunnel"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b54241c 8b742418 8d42fc 3bf0 0f86f9fcffff 3bf2 }
		$sequence_1 = { 8a542410 8a442414 8d7702 6a00 8d7e09 }
		$sequence_2 = { 8a442430 8b4f58 888778010000 83c40c c7811c04000001000000 eb6d ba01ff0000 }
		$sequence_3 = { 8b11 83c202 52 e8???????? }
		$sequence_4 = { 8a0c30 84c9 0f84fc010000 0fb6c9 }
		$sequence_5 = { 8a0b 43 84c9 75f9 2bde 3bda 0f87e8070000 }
		$sequence_6 = { e8???????? 99 b960000000 f7f9 }
		$sequence_7 = { 8d84248c000000 50 55 c60730 c7442430ff000000 e8???????? }
		$sequence_8 = { eb6d ba01ff0000 663bda 7522 8b442434 }
		$sequence_9 = { 8a4c2410 8a542414 8d5f09 880b 885301 8b7558 68???????? }
		$sequence_10 = { c7010c000000 5e 5d c3 6a00 }
		$sequence_11 = { 8b02 83c002 895f04 895f08 }
		$sequence_12 = { 8b5620 895020 8b4e10 894810 eb02 33c0 }
		$sequence_13 = { 894818 8b16 8910 8b4e14 }
		$sequence_14 = { e8???????? 8bf8 83c404 897dec 33db }
		$sequence_15 = { 895e18 c645fc01 6a18 895e28 e8???????? 83c404 }
		$sequence_16 = { e8???????? 8918 8d550c 8d4740 }
		$sequence_17 = { e8???????? 83c404 897710 897714 897718 }
		$sequence_18 = { 8b7508 33db 6a18 895e08 }
		$sequence_19 = { 83c404 8945b0 8b45b4 50 }
		$sequence_20 = { c685c6e0ffff8a c685c7e0fffff9 c685c8e0ffff50 c685c9e0ffffe4 }
		$sequence_21 = { c685c5feffff22 c685c6feffffeb c685c7feffff63 c685c8feffff51 }
		$sequence_22 = { c685c5fdffff6b c685c6fdfffff3 c685c7fdffff13 c685c8fdffff4d c685c9fdffff86 c685cafdffff4d c685cbfdffff16 }
		$sequence_23 = { c685c6e1ffff44 c685c7e1ffff05 c685c8e1ffff17 c685c9e1ffff07 }

	condition:
		7 of them and filesize <4634440
}
