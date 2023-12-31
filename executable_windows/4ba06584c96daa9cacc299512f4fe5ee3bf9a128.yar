rule win_aveo_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.aveo."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.aveo"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8d8c241a020000 e8???????? eb3f 3c33 }
		$sequence_1 = { 7524 a1???????? a3???????? a1???????? c705????????94894000 }
		$sequence_2 = { 56 6a7f 8d8579ffffff 6a00 }
		$sequence_3 = { 8975e0 8db1e01a4100 8975e4 eb2b 8a4601 84c0 }
		$sequence_4 = { 8d95f4feffff 52 8d85f4fbffff 68???????? 50 e8???????? 83c41c }
		$sequence_5 = { 8b04bd002e4100 0500080000 3bf0 0f8396000000 f6460401 755b 837e0800 }
		$sequence_6 = { 85c0 7516 a1???????? 8b0d???????? a3???????? 890d???????? }
		$sequence_7 = { 8b55f4 885c3701 8b5d08 03d1 807c1a032d 7438 }
		$sequence_8 = { 8b5808 8bf1 8b08 51 }
		$sequence_9 = { 50 6a00 ffd6 6a64 ffd7 }

	condition:
		7 of them and filesize <180224
}
