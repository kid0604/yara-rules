rule win_nosu_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.nosu."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nosu"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff74240c 57 8d4101 8987b8040000 8d4710 50 6a00 }
		$sequence_1 = { 56 8b742424 57 03f5 8bfa 8bce }
		$sequence_2 = { 50 6a00 51 8d45f8 50 ff15???????? 85c0 }
		$sequence_3 = { ff742470 83c108 8d9648010000 6a08 51 52 33d2 }
		$sequence_4 = { 8d4102 42 50 8aca e8???????? }
		$sequence_5 = { 59 85c0 7471 8b742408 8d442410 50 8d442410 }
		$sequence_6 = { 8d442410 56 57 50 ff32 33c0 8bf1 }
		$sequence_7 = { 8bf0 89742418 85f6 0f8455010000 ff742414 8b542414 8bce }
		$sequence_8 = { 8d8628020000 8bf8 89442414 85ff 745b 8d87c0000000 89442410 }
		$sequence_9 = { 85c0 747e 8bd6 89742410 397500 7673 8b4510 }

	condition:
		7 of them and filesize <513024
}
