rule win_snifula_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.snifula."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.snifula"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83c414 68???????? 56 68???????? 8bd8 8945fc e8???????? }
		$sequence_1 = { 8d4df4 51 8b4e04 03c8 51 e8???????? }
		$sequence_2 = { 53 eb46 8bc3 2b45fc 8945f4 40 50 }
		$sequence_3 = { ff75f8 ff75f4 68???????? 56 ff15???????? 83c414 68???????? }
		$sequence_4 = { 8b45f8 5f c9 c20400 56 }
		$sequence_5 = { 85c0 7405 397d08 7407 c7461403000000 f70600000040 7407 }
		$sequence_6 = { 8b0424 59 c20400 57 6a0c 6a40 33ff }
		$sequence_7 = { bf???????? eb19 6a0d 5d 68???????? }
		$sequence_8 = { 6a00 ff35???????? ffd6 53 8bf0 }
		$sequence_9 = { 53 a3???????? ff15???????? a3???????? 3bc3 7505 6a02 }

	condition:
		7 of them and filesize <188416
}
