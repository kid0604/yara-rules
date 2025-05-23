rule win_alina_pos_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.alina_pos."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.alina_pos"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7439 6828010000 8d85d0feffff 6a00 50 e8???????? 83c40c }
		$sequence_1 = { 2bc8 51 03fe 03f8 }
		$sequence_2 = { 39410c 7305 8b4908 eb04 8bd1 8b09 }
		$sequence_3 = { 3975e8 720c 8b45d4 50 e8???????? 83c404 32c0 }
		$sequence_4 = { 53 ff15???????? 85c0 75cd 56 e8???????? }
		$sequence_5 = { 3bc1 7763 83ceff 3bc8 }
		$sequence_6 = { 8bd1 2bd0 83faff 7306 8bf2 85f6 }
		$sequence_7 = { 03fe 03f8 03d0 57 52 }
		$sequence_8 = { 8a0e 8845c8 884dd4 7562 8d7ddc 8bc3 e8???????? }
		$sequence_9 = { 8d85f0feffff 50 6805010000 ff15???????? }
		$sequence_10 = { 6800000080 50 ff15???????? 85c0 }
		$sequence_11 = { 8bf0 8d45ec 50 6800040000 }
		$sequence_12 = { 85c9 7406 c70100000000 6a00 6a00 6a00 }
		$sequence_13 = { ff15???????? 50 6a73 68???????? }
		$sequence_14 = { 8b45ec 85c0 7464 03f8 }
		$sequence_15 = { 6a13 53 c645f000 c745d00a000000 }
		$sequence_16 = { ff15???????? 50 6a70 68???????? }
		$sequence_17 = { ff15???????? 85c0 0f95c0 eb02 b001 }
		$sequence_18 = { 64a300000000 6800100000 e8???????? 8b5d08 }
		$sequence_19 = { ff15???????? 50 6a5f 68???????? }
		$sequence_20 = { 6810270000 ff15???????? 6a00 6a0f }
		$sequence_21 = { e8???????? 83c418 6860ea0000 ff15???????? }
		$sequence_22 = { 6a00 6800000080 6a00 6a00 68???????? 68???????? 68???????? }
		$sequence_23 = { 83c418 e8???????? 8b3d???????? 8bf0 }
		$sequence_24 = { 8d4720 50 ff15???????? 8b4718 }
		$sequence_25 = { 57 6800040000 52 8d85fcfbffff }
		$sequence_26 = { 85f6 743e 83feff 7439 }
		$sequence_27 = { d1e8 352083b8ed eb02 d1e8 8901 }
		$sequence_28 = { c7850cffffff00000000 8b450c 50 8d4dd8 51 }
		$sequence_29 = { 81ec1c010000 53 56 57 51 }
		$sequence_30 = { 83e004 0f8412000000 83a50cfffffffb 8d8de4feffff e9???????? }
		$sequence_31 = { b947000000 b8cccccccc f3ab 59 }
		$sequence_32 = { 8b45e8 8b7018 d1ee 8b4de8 e8???????? }
		$sequence_33 = { 8b4508 8945dc eb52 8b45dc 33d2 }
		$sequence_34 = { 56 57 8dbdc8fcffff b9cb000000 }
		$sequence_35 = { e9???????? c3 8b542408 8d420c 8b8a94feffff 33c8 }
		$sequence_36 = { e8???????? 488d154f270200 488d4c2420 e8???????? cc 48895c2410 }
		$sequence_37 = { 4533c9 c74424283f000f00 4533c0 894c2420 48c7c101000080 ff15???????? }
		$sequence_38 = { 56 57 4156 4883ec40 48c7442438feffffff 48895c2468 48896c2470 }
		$sequence_39 = { 4c8bea 4b8b8cf770e80200 4c8b15???????? 4883cfff 418bc2 498bd2 4833d1 }
		$sequence_40 = { ba7c000000 41b901000000 4c8d05844b0200 488d4c2428 e8???????? }
		$sequence_41 = { 4883ec20 8b1d???????? eb1d 488d05971d0200 }

	condition:
		7 of them and filesize <2498560
}
