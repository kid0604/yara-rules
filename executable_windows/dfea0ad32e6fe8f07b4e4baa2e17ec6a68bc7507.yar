rule win_taintedscribe_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.taintedscribe."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.taintedscribe"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 5e b800020000 5b 5d c20c00 c6461401 }
		$sequence_1 = { 895634 0fb755e4 894630 894638 894640 0fb745e8 c1e210 }
		$sequence_2 = { 8bf8 f3a5 8b4b28 83c414 85c9 7518 5f }
		$sequence_3 = { 017e54 57 53 50 e8???????? 83c418 }
		$sequence_4 = { 81cf00000040 eb06 81cf00000080 81cf00000001 897da4 85c0 }
		$sequence_5 = { 8bc2 d3e0 83c40c 098658af0100 8d0419 89865caf0100 83f810 }
		$sequence_6 = { 668985ecfbffff e8???????? 83c40c 85db 7410 }
		$sequence_7 = { 83c418 894310 895314 8bb57cffffff 85f6 7421 8d55a4 }
		$sequence_8 = { 7d06 89b588fbffff 8b5350 8b4b2c 8b7b38 89958cfbffff }
		$sequence_9 = { 7407 3d50450000 7507 814da400004000 8b7da4 8b5d9c 8b4580 }

	condition:
		7 of them and filesize <524288
}
