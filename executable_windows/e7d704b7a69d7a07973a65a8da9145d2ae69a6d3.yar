rule win_ketrum_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.ketrum."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ketrum"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 57 33ff ffb760314200 ff15???????? 898760314200 83c704 }
		$sequence_1 = { 03f2 f7d7 0bfe 33fa 037df0 8dbc0fa111084e c1cf0b }
		$sequence_2 = { ffb5f0bfffff ff15???????? ffb5f0bfffff ff15???????? ffb5e4bfffff ffb5f4bfffff }
		$sequence_3 = { 59 85c0 744d b9???????? 8bc1 }
		$sequence_4 = { ebcb 8b4de0 8b01 8b4004 03c1 }
		$sequence_5 = { 50 e8???????? 83c448 ffb5f0cbffff e8???????? }
		$sequence_6 = { 56 33db 8d85fcfbffff 53 50 e8???????? }
		$sequence_7 = { b9???????? 8995e8cbffff 3bc6 7321 898de8cbffff 898df4cbffff 3935???????? }
		$sequence_8 = { 8b4004 8bd1 c1ea03 8d549a04 }
		$sequence_9 = { 720a b857000780 e8???????? 8b4e14 }
		$sequence_10 = { 57 c785d4eeffff01000000 ff15???????? c68533efffff00 89b520efffff 8b8520efffff }
		$sequence_11 = { 50 6a26 ffb538efffff ff15???????? 85c0 }
		$sequence_12 = { eb0d 8b75bc 8bcf e8???????? 83c71c 3b7da8 }
		$sequence_13 = { 50 e8???????? 59 85c0 753b ff750c }
		$sequence_14 = { e8???????? 83a7c801000000 b830750000 8987d0010000 8987d4010000 c787cc01000060ea0000 }
		$sequence_15 = { 663b16 730e c70308000000 eb0f 668b06 668907 }

	condition:
		7 of them and filesize <4599808
}
