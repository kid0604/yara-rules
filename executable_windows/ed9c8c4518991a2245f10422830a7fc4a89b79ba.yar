rule win_webc2_bolid_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.webc2_bolid."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_bolid"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8801 eb09 51 e8???????? 83c404 8b442450 899c2480000000 }
		$sequence_1 = { 8bcd e8???????? c644245405 bf???????? 83cdff 33c0 }
		$sequence_2 = { c1f905 83e61f 88450b 8d3c8dc01f4100 c1e603 8b0f 80650b48 }
		$sequence_3 = { 83ec10 8a45f3 53 8bd9 }
		$sequence_4 = { 85c0 763e 8a536c 8d7b6c 83ec10 }
		$sequence_5 = { 0fb641ff 0fb6d2 3bc2 0f8793000000 80880132410004 }
		$sequence_6 = { e8???????? c645fc0f 6a01 8d4da0 }
		$sequence_7 = { 6a01 8d8d34ffffff c645fc16 e8???????? 8b45a4 85c0 }
		$sequence_8 = { 8b4f04 8b5508 03ca 2bc6 50 }
		$sequence_9 = { c7851cffffff01010000 ff15???????? 8a4d1b 53 884d88 8d4d88 8bf0 }

	condition:
		7 of them and filesize <163840
}