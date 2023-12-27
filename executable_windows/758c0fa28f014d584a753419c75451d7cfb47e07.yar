rule win_upas_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.upas."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.upas"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 744b 3935???????? 7443 6a00 6a1c 8d45e4 50 }
		$sequence_1 = { 8b442404 8b4004 ff80b8000000 c605????????00 83c8ff c3 53 }
		$sequence_2 = { 75e7 50 e8???????? 59 33c0 }
		$sequence_3 = { 40 eb5f 56 8b35???????? 68???????? 57 ffd6 }
		$sequence_4 = { 85c0 0f88a1000000 8d4304 3bc7 }
		$sequence_5 = { 83ceff 3bde 0f845bffffff be???????? 56 }
		$sequence_6 = { 0f8587000000 8b45fc 2b45f8 c645dce9 }
		$sequence_7 = { 6a12 56 68???????? 8d4df8 8bf8 e8???????? 50 }
		$sequence_8 = { 57 53 e9???????? 8b4514 8b1d???????? 57 6a08 }
		$sequence_9 = { 8d8598faffff 50 57 ff15???????? 57 ff15???????? ff7508 }

	condition:
		7 of them and filesize <114688
}