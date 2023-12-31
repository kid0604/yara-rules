rule win_zebrocy_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.zebrocy."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zebrocy"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 014158 11515c e8???????? dc6360 }
		$sequence_1 = { 837ddc00 0f8c9d000000 7f08 85f6 0f8493000000 }
		$sequence_2 = { 0103 83c41c 5b 5e }
		$sequence_3 = { 0110 8b7dd4 ba???????? 89470c }
		$sequence_4 = { 56 8b7508 57 8b3d???????? 68007f0000 33db }
		$sequence_5 = { e8???????? 8bc8 8bc6 c644246001 e8???????? be10000000 3974242c }
		$sequence_6 = { 0103 8b0e ba???????? e8???????? }
		$sequence_7 = { 8b8c2480000000 6a00 56 6a00 6a00 6a00 6a00 }
		$sequence_8 = { 0102 8b45d4 89500c 89c1 }
		$sequence_9 = { 014150 8b550c 115154 014158 }
		$sequence_10 = { 8d95b0f7ffff e8???????? c645fc0e 8b8dc4f6ffff 6aff 83c102 }
		$sequence_11 = { 0103 31d2 85ff 8b03 }
		$sequence_12 = { 68???????? e8???????? 85ff 0f84ee000000 8d1438 8955fc }
		$sequence_13 = { b9???????? 8dbdb0f7ffff e8???????? 3ac3 7437 }
		$sequence_14 = { 50 e9???????? 83f802 0f8525010000 83ec1c }
		$sequence_15 = { 0110 5e 5f 5d }

	condition:
		7 of them and filesize <393216
}
