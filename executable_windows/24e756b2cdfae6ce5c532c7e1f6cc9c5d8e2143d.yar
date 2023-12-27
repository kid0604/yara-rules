rule win_lightbunny_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.lightbunny."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lightbunny"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 90 8b45e4 6a00 56 }
		$sequence_1 = { 3bc8 7532 68???????? e8???????? }
		$sequence_2 = { c7861c10000000000000 81c624100000 81fe???????? 0f8c0effffff 5f 5e b801000000 }
		$sequence_3 = { 83c404 8bf8 0fb7460c 50 ff7608 }
		$sequence_4 = { 741e 0524100000 41 3d???????? 7cef 5f }
		$sequence_5 = { 33c5 8945fc 56 8bf1 8d95fcfeffff }
		$sequence_6 = { 85db 7507 c746349c3a4100 57 ff7634 }
		$sequence_7 = { 0f85d2000000 80bdfdfeffff01 0f85c5000000 8b85fffeffff 57 }
		$sequence_8 = { 81fe???????? 0f8c0effffff 5f 5e }
		$sequence_9 = { 8b148520ae4100 8a4c1a2d f6c104 7419 8a441a2e 80e1fb }

	condition:
		7 of them and filesize <2376704
}