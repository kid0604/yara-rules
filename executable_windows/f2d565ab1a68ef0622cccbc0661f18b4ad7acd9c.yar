rule win_darkmegi_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.darkmegi."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkmegi"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0f8491000000 8d542408 52 e8???????? 83c404 85c0 7504 }
		$sequence_1 = { 8d4c2418 6a10 51 8dbc24ac030000 83c9ff }
		$sequence_2 = { 51 e8???????? 8bf0 83c408 85f6 741c }
		$sequence_3 = { 55 c744242810000000 ff15???????? 83f8ff }
		$sequence_4 = { 85c0 0f8420010000 8d842468010000 50 6804010000 }
		$sequence_5 = { f7d1 49 85c9 7e29 33c0 8a0432 }
		$sequence_6 = { b941000000 33c0 8d7c2414 5b f3ab 837c240c05 7556 }
		$sequence_7 = { 68???????? 68???????? 6802000080 e8???????? 83c40c eb06 }
		$sequence_8 = { 57 e8???????? 83c408 85c0 0f8491000000 }
		$sequence_9 = { 5d 33c0 5b 81c474100000 c3 }

	condition:
		7 of them and filesize <90304
}
