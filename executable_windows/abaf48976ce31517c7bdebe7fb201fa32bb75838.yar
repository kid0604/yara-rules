rule win_allaple_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.allaple."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.allaple"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 53 e8???????? 33ff 89bdfcfbffff 6800020000 8d8500feffff 50 }
		$sequence_1 = { e8???????? 83c40c 0305???????? 0345b0 05a1ebd96e 50 e8???????? }
		$sequence_2 = { eb2a 83c604 833e00 75eb 8b35???????? 81c700100000 }
		$sequence_3 = { 5f c3 8bff 55 8bec 57 56 }
		$sequence_4 = { 83c408 8d8d78ffffff 51 8d8538ffffff 50 e8???????? }
		$sequence_5 = { 53 60 8b7d0c 8b7508 8b4e3c 03f1 0fb74606 }
		$sequence_6 = { 8bca d3f8 8845d4 c745d80f000000 eb09 8b45d8 83e801 }
		$sequence_7 = { 83c704 8b75fc 2bfe 8b4d10 8939 }
		$sequence_8 = { 53 e8???????? c70352414853 897b04 ff750c e8???????? }
		$sequence_9 = { 8b55e0 d1c2 8955e0 8b45f0 0345ec 038554ffffff 8b4ddc }

	condition:
		7 of them and filesize <253952
}
