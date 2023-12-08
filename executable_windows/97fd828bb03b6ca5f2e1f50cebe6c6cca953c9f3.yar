rule win_beatdrop_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.beatdrop."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.beatdrop"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 418b4c2408 4d89f9 488d443500 4803742460 4889c7 f3a4 }
		$sequence_1 = { e8???????? eb05 49ff442418 4c89e0 }
		$sequence_2 = { 4533848500080000 89d8 c1eb10 418b549500 c1e818 4333949d000c0000 0fb6db }
		$sequence_3 = { 4c894c2458 4c8d4c2458 4c894c2428 e8???????? 4883c438 c3 4154 }
		$sequence_4 = { 4d89e6 e8???????? 4c8b2e 4c8b7e08 4889c1 4889c5 e8???????? }
		$sequence_5 = { 4189cd 89d3 89c1 c1eb18 41c1ea18 }
		$sequence_6 = { 448b8d0c010000 4489d0 48899510010000 410fcb d1e8 44335d00 }
		$sequence_7 = { 43339cac00080000 448b742414 4533848c00080000 0fb6ef 4489c1 448b442408 478b0484 }
		$sequence_8 = { 4c89e1 e8???????? 4c89e9 8844242f e8???????? 8a44242f 4883c448 }
		$sequence_9 = { 410fb61414 410fb60404 4e8d74b500 41c1e318 488b8c2488000000 41333e 4133460c }

	condition:
		7 of them and filesize <584704
}
