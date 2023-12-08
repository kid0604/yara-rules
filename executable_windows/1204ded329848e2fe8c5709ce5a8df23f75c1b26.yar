rule win_kurton_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.kurton."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kurton"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8d9424ac040000 51 52 50 }
		$sequence_1 = { 55 68e8030000 ff15???????? 8b467c 8b2d???????? 53 50 }
		$sequence_2 = { 8bc6 83e61f c1f805 59 8b0485a05b0210 8d0cf6 8064880400 }
		$sequence_3 = { 33c0 c1e902 f3a5 8bca 8d5570 83e103 f3a4 }
		$sequence_4 = { 894508 8bc6 c1f805 8d1c85a05b0210 8bc6 83e01f }
		$sequence_5 = { 8d4c242c 50 57 e8???????? 68???????? e8???????? 83c404 }
		$sequence_6 = { 668b886aca0110 894a78 33c9 668b8868ca0110 898a84000000 33c9 }
		$sequence_7 = { 8b0c8da05b0210 f644810401 8d0481 7403 8b00 c3 e8???????? }
		$sequence_8 = { 7509 8b0c85802b0210 eb07 8b0c85b42b0210 }
		$sequence_9 = { 56 8bf1 57 8b8c24a8080000 68a20f0000 50 51 }

	condition:
		7 of them and filesize <344064
}
