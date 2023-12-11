rule win_moure_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.moure."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.moure"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 007604 00d7 83c40c 85c0 74e7 00750c }
		$sequence_1 = { 8bc8 00cc cc 8b00 55 8bec 8b4508 }
		$sequence_2 = { 59 81c1f8ffffff 2be1 59 5b 53 4b }
		$sequence_3 = { 2be0 58 8b9b80000000 035d08 56 }
		$sequence_4 = { 56 689c604000 e8???????? ef }
		$sequence_5 = { ff15???????? 85c0 0f8484000000 0075dc 0075d8 }
		$sequence_6 = { 7518 007508 50 e8???????? 57 8bce }
		$sequence_7 = { a892 b4bf bfc5803416 7389 }
		$sequence_8 = { 56 6a1f 007014 007010 e8???????? a1???????? eb05 }
		$sequence_9 = { 81c8ffffffff f7d0 81c0f8ffffff 2be0 58 2d1a2978a0 }

	condition:
		7 of them and filesize <188416
}
