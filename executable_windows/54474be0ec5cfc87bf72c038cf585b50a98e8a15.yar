rule win_industroyer2_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.industroyer2."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.industroyer2"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b4dfc 8b55f4 8b048a 89857cffffff }
		$sequence_1 = { 894dfc 8b45fc 0fb64804 83f968 7404 32c0 eb75 }
		$sequence_2 = { eb09 8b4df8 83c101 894df8 8b55fc 0fb64214 83e80a }
		$sequence_3 = { 8b45fc 8b4df8 894c9010 837df800 740f 8b55fc 8b420c }
		$sequence_4 = { c64014f0 c745f800000000 eb09 8b4df8 83c101 894df8 }
		$sequence_5 = { 8b55bc 8955ac 8b45c0 8945b0 8b4db4 2b4dac 8b55b8 }
		$sequence_6 = { 7509 c745d801000000 eb07 c745d800000000 8b4d0c 8a55d8 889146000100 }
		$sequence_7 = { 0fb6d0 85d2 741b 6a00 8d45ec 50 8b4df4 }
		$sequence_8 = { 0355ec 0fbe8256050100 85c0 0f8581030000 c745f400000000 eb09 8b4df4 }
		$sequence_9 = { 85c9 750a b89cffffff e9???????? 837d08ff 7576 }

	condition:
		7 of them and filesize <100352
}