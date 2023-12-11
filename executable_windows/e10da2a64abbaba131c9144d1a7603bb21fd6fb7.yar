rule win_gozi_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.gozi."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gozi"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff75dc 8f05???????? eb54 68???????? e8???????? }
		$sequence_1 = { de7e75 cd18 4a 51 d2b8c512294e 8c8873cd58c8 17 }
		$sequence_2 = { 3bde 59 7505 83c8ff eb41 53 ff75f8 }
		$sequence_3 = { 50 e8???????? 5f 5e 83c570 c9 }
		$sequence_4 = { fece 56 d2ca 0fbed0 }
		$sequence_5 = { 50 e8???????? 3b457c 8b4d78 }
		$sequence_6 = { 55 8bec 8d8742050000 8b00 }
		$sequence_7 = { 6802000080 ff15???????? 85c0 7515 8d45e4 50 }
		$sequence_8 = { 3a56b9 036890 2b02 9a102a6715fb53 31db b0a6 46 }
		$sequence_9 = { c1e606 033485e00c4400 c745e401000000 33db 395e08 }
		$sequence_10 = { 0facea12 f6de 0fbaf696 8b4de8 894dfc 8b55f4 }
		$sequence_11 = { b6c6 e8???????? 6af4 dbe9 68912b4384 2383e08985e4 }
		$sequence_12 = { 895590 8b558c 0b5590 742a }
		$sequence_13 = { d3e0 90 48 9e c1905ffb6daf6b }
		$sequence_14 = { 33db 56 895df4 e8???????? 8b7d08 8b8788000000 }
		$sequence_15 = { 8b7508 c7465cf8934300 83660800 33ff }
		$sequence_16 = { 89843d64fcffff 83c704 83c64c ff4dfc 75da }
		$sequence_17 = { 8b7804 897de4 e8???????? 8b5808 895de0 c745fc01000000 }
		$sequence_18 = { e8???????? 8945bc 8955c0 ff75c0 }
		$sequence_19 = { 4e 0fb3ce 0fbaf6b6 0ad0 8ad0 }
		$sequence_20 = { d2ee b65e feca 0fbaf2a2 b616 }
		$sequence_21 = { 2383e08985e4 0572b6e2f4 fd 4e 128b42926614 12a502b346d1 41 }
		$sequence_22 = { 5b 53 8d9feb040000 c70300000000 5b }
		$sequence_23 = { 50 ff75d8 ff15???????? 8945e0 3bc7 0f840e010000 68fa000000 }
		$sequence_24 = { 8d9724070000 52 50 8d87f2030000 ff10 }
		$sequence_25 = { 63743200 c808bf35 6963c03caff3da c9 50 }
		$sequence_26 = { feca 4a c0caca 86d6 }
		$sequence_27 = { 8bec 81ec44020000 8d45fc 50 8d85fcfeffff }
		$sequence_28 = { 50 8d8769030000 ff10 83c40c }
		$sequence_29 = { ff75f8 50 e8???????? ff75f8 8d8772060000 }
		$sequence_30 = { b87e8da638 e022 3a56b9 036890 }
		$sequence_31 = { be84f7c34f 10ba810b7f57 a4 8c6a38 }

	condition:
		7 of them and filesize <568320
}
