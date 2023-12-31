rule win_matanbuchus_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.matanbuchus."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.matanbuchus"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 3b55e0 750f 8b45f8 8b4ddc 0fb71441 }
		$sequence_1 = { 8d95b8feffff 52 8b45fc 0345ec 50 }
		$sequence_2 = { 668b4d0c 66894df4 837d0800 0f8401010000 8b5508 8b423c }
		$sequence_3 = { 8b450c 50 8b4d08 51 683afd800e }
		$sequence_4 = { 8955ec 0fb745fc 8b4dd8 668b1441 668955f8 }
		$sequence_5 = { 833d????????00 7517 8b450c 50 8b4d08 51 68a48c9471 }
		$sequence_6 = { 837df000 7424 8b4df8 8a11 8855ff }
		$sequence_7 = { 51 8b55f0 52 6b45f828 8b4dfc 038c0534fdffff }
		$sequence_8 = { 8955ec 0fb745fc 8b4dd8 668b1441 668955f8 eb0f }
		$sequence_9 = { 8b550c 3b55e0 750f 8b45f8 }

	condition:
		7 of them and filesize <2056192
}
