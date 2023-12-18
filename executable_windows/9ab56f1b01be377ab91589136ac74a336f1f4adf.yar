rule win_moriagent_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.moriagent."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.moriagent"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { b802000000 eb05 b801000000 33ff }
		$sequence_1 = { cc 488bc8 e8???????? 48897d00 48c745080f000000 c645f000 488b4528 }
		$sequence_2 = { cc 488bc8 e8???????? 48897da0 48c745a80f000000 c6459000 }
		$sequence_3 = { cc 488bc8 e8???????? 48897d18 48c745200f000000 c6450800 }
		$sequence_4 = { 83bd98efffff10 8bb5c4efffff 8b8d94efffff 660f7ec8 51 0f43d0 }
		$sequence_5 = { cc 488bc8 e8???????? 48897dd0 48c745d80f000000 c645c000 }
		$sequence_6 = { cc 488bc8 e8???????? 48897dc0 48c745c80f000000 c645b000 }
		$sequence_7 = { cc 488bc8 e8???????? 48897d20 48c745280f000000 c6451000 }
		$sequence_8 = { 8d8de4feffff e9???????? 8d8d30ffffff e9???????? 8d8dccfeffff }
		$sequence_9 = { 0f87df160000 52 51 e8???????? 8b85e8eeffff }
		$sequence_10 = { eb06 8bb5e4eeffff 8b857cefffff 85c0 0f84bd080000 80bdc7eeffff00 }
		$sequence_11 = { c785e0feffff0f000000 c685ccfeffff00 6a04 68???????? c7411000000000 c741140f000000 c60100 }
		$sequence_12 = { 0f1006 8b85e8eeffff 0f1185b4efffff f30f7e4610 660fd685c4efffff c7461000000000 c746140f000000 }
		$sequence_13 = { c746140f000000 c60600 8b5d1c 8d4d08 8b5508 8d7d08 8b4518 }
		$sequence_14 = { cc 488bc8 e8???????? 48897de0 48c745e80f000000 c645d000 }

	condition:
		7 of them and filesize <1347904
}
