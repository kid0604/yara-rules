rule win_skipper_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.skipper."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.skipper"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6a00 6a03 68???????? 68???????? 6a50 }
		$sequence_1 = { 59 5d c3 55 8bec 33c0 50 }
		$sequence_2 = { e8???????? 6804010000 e8???????? 6804010000 8bf8 6a00 57 }
		$sequence_3 = { ff15???????? 6a00 6a00 6a00 6a00 50 ff15???????? }
		$sequence_4 = { 50 e8???????? 6bc064 2bf0 6bf67b 56 }
		$sequence_5 = { 297d08 8b8df4feffff 41 81e1ff000080 7908 49 }
		$sequence_6 = { 7905 48 83c8f0 40 0fb60438 0fb6ca 03d8 }
		$sequence_7 = { e8???????? 6800803801 6a00 ff37 e8???????? }
		$sequence_8 = { 6800308000 6a00 6a00 68???????? }
		$sequence_9 = { e8???????? 83c404 6a00 6a64 52 }
		$sequence_10 = { 4863d0 420fb60432 4403c0 4403c6 4181e0ff000080 7d0d 41ffc8 }
		$sequence_11 = { 4181e2ff000080 7d0d 41ffca 4181ca00ffffff 41ffc2 0fb6c1 4c8d0424 }
		$sequence_12 = { 888deffeffff 0fb655fc 0fb645f8 8a8c15f0feffff }
		$sequence_13 = { ffc9 81c900ffffff ffc1 4863c1 0fb61404 4403d2 4181e2ff000080 }
		$sequence_14 = { 3b5514 0f8dcf000000 8b45f8 83c001 25ff000080 7907 48 }
		$sequence_15 = { 8802 ffc0 488d5201 3d00010000 7cf1 448bc1 448bc9 }
		$sequence_16 = { ebd0 c785e8feffff00000000 c785e0feffff00000000 eb0f 8b85e0feffff }
		$sequence_17 = { 83c001 8985e4feffff 81bde4feffff00010000 7d15 }
		$sequence_18 = { 8bc2 c1e81f 03d0 418bc1 8d1492 03d2 }
		$sequence_19 = { 4963e9 498bf8 488d1424 448bd1 }
		$sequence_20 = { 410fb6c0 488d1424 41ffc1 4803d0 48ffc3 }
		$sequence_21 = { 48ffc3 0fb602 8843ff 408832 4181f900010000 7c9a 488bdd }
		$sequence_22 = { 81e2ff000080 7908 4a 81ca00ffffff 42 0fb6d2 8a8415f0feffff }
		$sequence_23 = { 49 81c900ffffff 41 898de8feffff 8b85e0feffff 8a8c05f0feffff }
		$sequence_24 = { 6a0b 68???????? 8b15???????? 52 68???????? e8???????? 83c414 }
		$sequence_25 = { 8811 e9???????? b001 8b4df4 }
		$sequence_26 = { 488bcf ff15???????? 488b8c2400020000 4833cc e8???????? 488b9c2428020000 4881c410020000 }
		$sequence_27 = { 3d00010000 7d10 8a8c181d010000 8888b0a52300 }
		$sequence_28 = { e8???????? 488d4c2450 c744245094000000 ff15???????? }
		$sequence_29 = { 4c8d0518980000 488bcd 418bd7 e8???????? 33c9 }
		$sequence_30 = { 8b8dd4feffff 51 ff15???????? 8985e4feffff 6a04 }
		$sequence_31 = { c785d4feffff3a040000 eb0a c785d4feffffffff1f00 8b4508 }
		$sequence_32 = { 8b45fc ff34c51ca92300 53 57 e8???????? 83c40c }
		$sequence_33 = { 4883ec28 488d1549000000 488d0d3eec0000 4533c9 4533c0 }
		$sequence_34 = { 814df400010000 6a04 8d45f4 50 6a1f }
		$sequence_35 = { 4803d1 488d0d4ea70000 442bc6 488b0cc1 498b0c0c }
		$sequence_36 = { 80bddcfeffff00 7504 33c9 eb12 }
		$sequence_37 = { 6a00 50 8bce c745fc03000000 e8???????? }
		$sequence_38 = { 68???????? 8b85e8feffff 50 ff15???????? 8985d0feffff c785e0feffff00000000 }
		$sequence_39 = { 68ff000000 e8???????? 59 59 8b7508 8d34f570a02300 391e }
		$sequence_40 = { 8b4de0 8d0c8d20b72300 8901 8305????????20 8d9000080000 }
		$sequence_41 = { 4883ec20 488d3d43a40000 48393d???????? 742b b90c000000 }
		$sequence_42 = { 8945e4 8b7508 c7465cd8812300 33ff 47 }
		$sequence_43 = { e8???????? 4883c438 c3 4053 4883ec20 8bd9 4c8d442438 }
		$sequence_44 = { 488b13 498b0f 488d05d5300000 4889442450 488b85f0040000 4c8d442430 }

	condition:
		7 of them and filesize <262144
}