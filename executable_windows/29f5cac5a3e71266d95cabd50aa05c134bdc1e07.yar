rule win_hlux_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.hlux."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hlux"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 897d88 33c0 83f8c6 750b 83f8a6 7406 }
		$sequence_1 = { 0104b9 33c9 83c408 85c0 }
		$sequence_2 = { 8b5df8 33f6 8975f8 895de4 8b550c bffe7e12f7 }
		$sequence_3 = { 81fad7ce4bb3 7524 89b568ffffff 09d2 }
		$sequence_4 = { 0104bb 8d1447 89542418 e9???????? }
		$sequence_5 = { 83ffa2 7506 89bdacfeffff b88cb5634b 21c0 }
		$sequence_6 = { 83fa7b 7507 09d2 7403 8955e0 }
		$sequence_7 = { 0000 008365f0fe8b 4d 0883c108e918 }
		$sequence_8 = { 010f 840f 0000 008365f0fe8b }
		$sequence_9 = { 0101 c9 c3 6a10 }
		$sequence_10 = { 0009 1b4e01 e405 9d }
		$sequence_11 = { 8975cc 81ff8b12bf46 752c 8b15???????? 81fb5ae44462 741e 8b35???????? }
		$sequence_12 = { 0130 8b13 8b08 85d2 }
		$sequence_13 = { 09db 7503 895df0 897dd0 8975ec 81f918a08726 7503 }
		$sequence_14 = { 8db789211e87 83fa13 0f85e9000000 85c9 7503 894dc0 }
		$sequence_15 = { 0088aa4b0023 d18a0688078a 46 018847018a46 }

	condition:
		7 of them and filesize <3147776
}
