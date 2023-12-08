rule win_mm_core_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.mm_core."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mm_core"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83c008 c3 6a0c 68???????? e8???????? 8b7508 85f6 }
		$sequence_1 = { 85c0 7447 8b4db8 0fb711 81fa4d5a0000 }
		$sequence_2 = { 8906 3bc3 7417 8b06 034608 57 8d542430 }
		$sequence_3 = { 53 6a01 68000000c0 8b4508 50 ff15???????? 8bf8 }
		$sequence_4 = { 52 68???????? b92e010000 e8???????? 8bc7 83c40c 8d5001 }
		$sequence_5 = { 6a00 50 e8???????? 83c40c 33c0 33c9 8d542408 }
		$sequence_6 = { 83e71f c1e706 8b048540400110 8d44380c }
		$sequence_7 = { b923010000 e8???????? 8bd3 6a01 52 e8???????? 8d842490030000 }
		$sequence_8 = { 897c243c 85ff 0f84eb010000 55 55 6a03 55 }
		$sequence_9 = { 51 ffd3 8bf0 8b442414 85c0 }

	condition:
		7 of them and filesize <319488
}
