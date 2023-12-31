rule win_grimagent_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.grimagent."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.grimagent"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 55 8bec 83ec18 c745f400000000 c745f800000000 c745e800000000 8b4508 }
		$sequence_1 = { ebbe 8b550c 8955fc 8b450c 50 e8???????? }
		$sequence_2 = { 0fb711 3bc2 7514 8b45ec 83c002 }
		$sequence_3 = { 8b4dfc 0fb711 3bc2 7514 }
		$sequence_4 = { 8b4508 50 e8???????? 83c404 3945f4 0f8394000000 8b4df0 }
		$sequence_5 = { 0fb708 3bd1 7576 8b55f0 8955ec c745f800000000 eb09 }
		$sequence_6 = { 83ec0c 8b450c 8945f8 c745fc00220400 8b4dfc }
		$sequence_7 = { 8bec 8b4508 0fbe08 85c9 7426 8b5508 }
		$sequence_8 = { c745e801000000 b801000000 eb1a 8b4df0 }
		$sequence_9 = { 83c404 3945f8 750e c745e801000000 b801000000 }

	condition:
		7 of them and filesize <582656
}
