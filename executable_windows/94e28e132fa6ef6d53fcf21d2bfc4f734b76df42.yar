rule win_teslacrypt_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.teslacrypt."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.teslacrypt"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 338594000000 8985b4000000 338598000000 8985b8000000 }
		$sequence_1 = { 338598000000 8985b8000000 33859c000000 8985bc000000 }
		$sequence_2 = { 31f9 898d88000000 31ca 89958c000000 89d0 51 52 }
		$sequence_3 = { 3345fc 89451c 51 52 }
		$sequence_4 = { 0f8456030000 81ffc0000000 0f84ae010000 81ffe0000000 740a b8ffffffff }
		$sequence_5 = { 0f84ac010000 81ffe0000000 740a b8ffffffff e9???????? 83c510 }
		$sequence_6 = { 33550c 81ffa0000000 0f8456030000 81ffc0000000 }
		$sequence_7 = { 33859c000000 8985bc000000 51 52 89f2 }
		$sequence_8 = { 8d0db4304b00 8b542410 894224 890c24 e8???????? 8d0dc1304b00 8b542410 }
		$sequence_9 = { 31c9 8b4078 8b542434 01c2 }
		$sequence_10 = { 8b442410 25ffff0000 89e1 894104 8b442434 }
		$sequence_11 = { 894c2424 0f84db000000 31c0 8b4c2434 8b542428 034a24 }
		$sequence_12 = { 8b442424 8b4c2428 31d2 49 0fb730 89f7 c1ef0c }
		$sequence_13 = { 894c2418 e8???????? 8b4c241c 894c2428 }
		$sequence_14 = { 8b9180000000 8b742464 01d6 8b7c2464 8b54170c 83fa00 }
		$sequence_15 = { 3d04000080 894c2424 0f8591000000 8b44242c }

	condition:
		7 of them and filesize <1187840
}
