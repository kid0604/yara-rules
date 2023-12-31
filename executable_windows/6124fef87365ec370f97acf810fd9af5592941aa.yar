rule win_wormhole_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.wormhole."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wormhole"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 5e 81c410010000 c3 8b542421 33c0 8917 }
		$sequence_1 = { 6685c0 743f a1???????? 85c0 7531 }
		$sequence_2 = { 81ec0c010000 8b842414010000 8d542400 89442400 8b842418010000 }
		$sequence_3 = { 6a00 6a00 6a00 6808000100 51 e8???????? 83c414 }
		$sequence_4 = { 50 51 56 ff15???????? 85c0 7e15 6a78 }
		$sequence_5 = { 8b442418 3dff000000 7f59 6a0f }
		$sequence_6 = { 8b44241c 85c0 742d 3bc7 7202 8bc7 }
		$sequence_7 = { ff15???????? 85c0 7e15 6a78 8d542410 50 52 }
		$sequence_8 = { e8???????? 8b842408400000 56 57 c744240800000000 }
		$sequence_9 = { 3d06000100 7524 8b0d???????? 6a00 }

	condition:
		7 of them and filesize <99576
}
