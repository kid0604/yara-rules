rule win_zloader_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.zloader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zloader"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0fb7c0 57 50 53 e8???????? 83c40c }
		$sequence_1 = { 57 56 89ce ff7508 }
		$sequence_2 = { 0fb7450c 8d9df0feffff 53 50 ff7508 e8???????? }
		$sequence_3 = { 56 8b7508 8b7d0c 89f1 }
		$sequence_4 = { 57 56 e8???????? 81c410010000 }
		$sequence_5 = { 31db 8d8df0feffff e8???????? 89d8 81c404010000 5e }
		$sequence_6 = { 50 8b4508 ff30 57 }
		$sequence_7 = { 55 89e5 ff750c 6a00 ff7508 e8???????? 83c40c }
		$sequence_8 = { 56 50 a1???????? 89c1 }
		$sequence_9 = { 56 50 8b4510 31db }
		$sequence_10 = { 5e 8bc3 5b c3 8b44240c 83f8ff 750a }
		$sequence_11 = { c6043000 5e c3 56 57 8b7c2414 }
		$sequence_12 = { 50 56 56 56 ff7514 }
		$sequence_13 = { 59 84c0 7432 68???????? }
		$sequence_14 = { 68???????? ff742408 e8???????? 59 59 84c0 741e }
		$sequence_15 = { 50 89542444 e8???????? 03c0 }
		$sequence_16 = { 6689442438 8b442438 83c002 668944243a }
		$sequence_17 = { 6aff 50 e8???????? 8d857cffffff 50 }
		$sequence_18 = { 83c408 5e 5d c3 55 89e5 57 }
		$sequence_19 = { 99 52 50 8d44243c 99 52 50 }
		$sequence_20 = { 81c4a8020000 5e 5f 5b }
		$sequence_21 = { 89e5 53 57 56 81eca8020000 }
		$sequence_22 = { c7462401000000 c7462800004001 e8???????? 89460c }
		$sequence_23 = { e9???????? 31c0 83c40c 5e }
		$sequence_24 = { 83c414 c3 56 ff742410 }
		$sequence_25 = { 6a00 e8???????? 83c414 c3 8b542404 85d2 7503 }
		$sequence_26 = { e8???????? 03c0 6689442438 8b442438 }
		$sequence_27 = { 56 83ec18 89d6 89cf }
		$sequence_28 = { 0bc3 a3???????? e8???????? 8bc8 eb06 8b0d???????? 85c9 }
		$sequence_29 = { 8b45f0 8d4dec 894c240c 89442408 89742404 893c24 e8???????? }
		$sequence_30 = { 68???????? 56 e8???????? 5e c3 56 }
		$sequence_31 = { ebf7 8d442410 50 ff742410 ff742410 ff742410 }
		$sequence_32 = { 50 e8???????? 68???????? 56 e8???????? 8bf0 59 }
		$sequence_33 = { 56 68???????? ff742410 e8???????? 6823af2930 56 ff742410 }
		$sequence_34 = { 33db 68???????? 6880000000 50 e8???????? 83c410 }
		$sequence_35 = { 5b c3 8bc2 ebf7 8d442410 }
		$sequence_36 = { 33f6 e8???????? ff7508 8d85f0fdffff 68???????? }
		$sequence_37 = { 50 6a72 e8???????? 59 }
		$sequence_38 = { 8d4580 50 8d8578fdffff 50 68???????? 6804010000 ff7508 }
		$sequence_39 = { 56 57 ff750c 33db 68???????? 6880000000 }
		$sequence_40 = { ebf8 53 8b5c240c 55 33ed }

	condition:
		7 of them and filesize <1105920
}