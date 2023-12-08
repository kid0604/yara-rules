rule win_cerbu_miner_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.cerbu_miner."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cerbu_miner"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 48 8bf8 48 85c0 0f8426010000 48 }
		$sequence_1 = { 83632800 48 837f2800 48 8b7730 0f84b5000000 48 }
		$sequence_2 = { 8bec 44 3be0 44 0f47e8 44 896c2448 }
		$sequence_3 = { 41 0fb6f9 41 0fb6eb eb25 8d41a6 6683f807 }
		$sequence_4 = { ff4328 48 8b4318 8a08 48 ffc0 884b41 }
		$sequence_5 = { ff15???????? 48 3305???????? 48 8d15a23efeff 48 8bcb }
		$sequence_6 = { 48 894108 48 8b7918 48 83bf700b000000 742f }
		$sequence_7 = { 8bcc 4d 2bcf 0fb602 41 0fb60c11 41 }
		$sequence_8 = { ffc0 eb02 33c0 2bf8 42 8d040a 44 }
		$sequence_9 = { ffc3 48 2b4728 48 c1f803 48 3bd8 }

	condition:
		7 of them and filesize <1040384
}
