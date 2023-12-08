rule win_zxxz_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.zxxz."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zxxz"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c744242cfa000000 668994242c020000 e8???????? 83c424 8d4c240c 51 }
		$sequence_1 = { 8d4c2414 68fa000000 51 ffd5 83c40c }
		$sequence_2 = { 6a00 68ffff0000 68???????? 68???????? 6802000080 89742420 ff15???????? }
		$sequence_3 = { e8???????? 33d2 68f8000000 52 }
		$sequence_4 = { 68???????? 8d9c2414020000 8d942414010000 b9???????? e8???????? 8b35???????? 83c404 }
		$sequence_5 = { 56 33c0 68f8000000 50 }
		$sequence_6 = { ff15???????? 8b35???????? 68f4010000 ffd6 8b1d???????? 6a01 }
		$sequence_7 = { e8???????? 57 68fa000000 68???????? ffd5 8b761c }
		$sequence_8 = { 33cc e8???????? 81c408010000 c3 85f6 0f84b4000000 }
		$sequence_9 = { 2bc2 50 8d8c2410010000 51 68???????? e8???????? 8d842414020000 }

	condition:
		7 of them and filesize <4142080
}
