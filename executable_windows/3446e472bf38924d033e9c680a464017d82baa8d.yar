rule win_sienna_purple_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.sienna_purple."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sienna_purple"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e9???????? 8d8da8feffff c645fc00 e8???????? c6854bfdffff00 e9???????? 83fe01 }
		$sequence_1 = { e8???????? 83c408 85c0 7508 b81a270000 5e 5d }
		$sequence_2 = { e8???????? b001 5e 5d c3 81fae3040000 7511 }
		$sequence_3 = { 6a00 50 e8???????? 83c40c 8d8d7cffffff e8???????? 8b7d08 }
		$sequence_4 = { 8d4db8 660fd645b8 e8???????? 807d0800 8b45b0 8bc8 c645fc02 }
		$sequence_5 = { 833d????????00 0f85f3e0ffff 893d???????? e9???????? 81f9c74f0000 7578 833d????????00 }
		$sequence_6 = { 8bb5ecfeffff c1c806 33c8 8bc6 038d54ffffff 33c3 2385e4feffff }
		$sequence_7 = { 8bf8 85ff 0f84cedbffff 683c4f0000 e8???????? 8bd8 83c404 }
		$sequence_8 = { d3ee 81e6ff7f0000 894320 8975b8 83fe01 7d0a b8e6ffffff }
		$sequence_9 = { ff750c ffb514ffffff e8???????? 83c418 b901000000 898d1cffffff 85ff }

	condition:
		7 of them and filesize <2930688
}
