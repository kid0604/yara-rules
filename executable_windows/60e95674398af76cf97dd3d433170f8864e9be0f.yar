rule win_rover_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.rover."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rover"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 50 e8???????? 8b542428 8d4c241c 52 89442460 }
		$sequence_1 = { 898714030000 3bc3 750c 5f 5e b81b000000 5b }
		$sequence_2 = { 0f8498000000 8b30 85f6 0f848a000000 6a40 8d942438010000 }
		$sequence_3 = { 6a00 57 e8???????? 83c40c 85c0 0f8525020000 83fd03 }
		$sequence_4 = { 50 81ec38020000 a1???????? 33c4 89842430020000 53 55 }
		$sequence_5 = { ffd1 83c404 5f 5e c3 c787e0020000884f4400 8b87e0020000 }
		$sequence_6 = { 899db0040000 899db4040000 8b442428 8b38 8db5d8030000 e8???????? 8b0e }
		$sequence_7 = { 3d40270000 7405 83f80d 7555 46 663b74241c }
		$sequence_8 = { 55 68???????? e8???????? 83c408 85c0 740d 5f }
		$sequence_9 = { 8bbe00050000 8b4720 8b4f1c 83c70c 50 51 56 }

	condition:
		7 of them and filesize <704512
}
