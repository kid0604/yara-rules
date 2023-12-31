rule win_7ev3n_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.7ev3n."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.7ev3n"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e9???????? 8d8da0cdffff e8???????? 8d5801 }
		$sequence_1 = { e8???????? 33c0 c7458807000000 c7458400000000 66898574ffffff 8845fc 8b451c }
		$sequence_2 = { e8???????? 8bce 2bcf 3bc1 0f84a29c0000 8dbdd0dcffff }
		$sequence_3 = { 668985b4e6ffff f30f7e05???????? 660fd685a0e6ffff 0fb705???????? 668985a8e6ffff f30f7e05???????? 660fd68594e6ffff }
		$sequence_4 = { 66898524f5ffff f30f7e05???????? 660fd68510f5ffff 0fb705???????? 66898518f5ffff f30f7e05???????? 660fd68504f5ffff }
		$sequence_5 = { 742b 0fb611 0fb6c0 eb17 81fa00010000 7313 8a8764644500 }
		$sequence_6 = { 6685c9 75f0 66837dc858 7522 66837dca50 751b 33c9 }
		$sequence_7 = { 0f84725c0000 8dbd60eaffff 8d4f02 0f1f840000000000 668b07 83c702 }
		$sequence_8 = { a1???????? 898500feffff a1???????? 898504feffff 33c0 66898508feffff f30f7e05???????? }
		$sequence_9 = { 8d852cf4ffff 50 8d8dd0cdffff e8???????? 8bce 2bcf }

	condition:
		7 of them and filesize <803840
}
