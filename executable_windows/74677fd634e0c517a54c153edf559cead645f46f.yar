rule win_woodyrat_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.woodyrat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.woodyrat"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b45e0 895804 eb02 8bc1 8b4df4 64890d00000000 59 }
		$sequence_1 = { 8d4db4 e8???????? 83c418 50 8d45cc c645fc02 50 }
		$sequence_2 = { 8d4601 50 8d4dcc e8???????? 83bd7cffffff08 8bc8 8b4598 }
		$sequence_3 = { e8???????? 6a05 68???????? 8d8d6cfeffff c7857cfeffff00000000 c78580feffff0f000000 c6856cfeffff00 }
		$sequence_4 = { 83f81f 0f87d8010000 51 57 e8???????? 83c408 c745fcffffffff }
		$sequence_5 = { 8bc8 83781410 7202 8b08 83781004 753b 8b01 }
		$sequence_6 = { 740c ffb550ffffff ff9544ffffff 8b8548ffffff 83782000 7706 83781c00 }
		$sequence_7 = { c78574ffffff00000000 33c9 660fd6459c c745a400000000 c7459c00000000 894de8 894da0 }
		$sequence_8 = { 50 8d45e8 c745fc00000000 50 8bce e8???????? 837dec00 }
		$sequence_9 = { 83c408 8b45d0 40 893b 8d0cc0 8b45e0 }

	condition:
		7 of them and filesize <785408
}
