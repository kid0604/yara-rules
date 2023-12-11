rule win_phorpiex_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.phorpiex."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.phorpiex"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6a00 ff15???????? ff15???????? 50 e8???????? }
		$sequence_1 = { ff15???????? 85c0 740f 6a07 }
		$sequence_2 = { ff15???????? 85c0 741f 6880000000 }
		$sequence_3 = { 6a00 6a20 6a00 6a00 6a00 8b5508 52 }
		$sequence_4 = { e8???????? 83c410 6a00 6a02 6a02 }
		$sequence_5 = { 50 e8???????? 83c404 e8???????? e8???????? ff15???????? 6a00 }
		$sequence_6 = { e8???????? 99 b90d000000 f7f9 }
		$sequence_7 = { 6a01 6a00 68???????? e8???????? 83c40c 33c0 }
		$sequence_8 = { 52 ff15???????? 6a00 6a00 6a00 6a00 68???????? }
		$sequence_9 = { 68???????? ff15???????? 8d85f8fdffff 50 68???????? }
		$sequence_10 = { 52 683f000f00 6a00 68???????? 6802000080 ff15???????? 85c0 }
		$sequence_11 = { 6a01 ff15???????? ff15???????? b001 }
		$sequence_12 = { 6a00 6a00 682a800000 6a00 ff15???????? }
		$sequence_13 = { ff15???????? 6a00 ff15???????? 85c0 7418 ff15???????? }
		$sequence_14 = { f7f9 81c210270000 52 e8???????? 99 }
		$sequence_15 = { 8bec 83ec08 6a00 ff15???????? 85c0 7440 6a01 }
		$sequence_16 = { 7416 8b4df8 51 ff15???????? 8b55fc 52 e8???????? }
		$sequence_17 = { 3d00010000 7504 83c8ff c3 }
		$sequence_18 = { 50 e8???????? 59 59 85c0 7573 }
		$sequence_19 = { 6a21 50 e8???????? c60000 }
		$sequence_20 = { 3db7000000 7508 6a00 ff15???????? 6804010000 }
		$sequence_21 = { 83c40c e8???????? 99 b960ea0000 }
		$sequence_22 = { e8???????? 83c418 6a00 8d54240c 52 6880000000 }
		$sequence_23 = { 83c004 81f9???????? 7cdb eb0b }
		$sequence_24 = { 83feff 741e ff15???????? 3db7000000 }
		$sequence_25 = { 41 663bc2 72f7 53 33c0 56 57 }
		$sequence_26 = { 68e8030000 ff15???????? e8???????? be???????? }
		$sequence_27 = { 50 8d45ec 50 6805000020 }
		$sequence_28 = { 8d45f8 50 8d45e4 50 6805000020 }

	condition:
		7 of them and filesize <2490368
}
