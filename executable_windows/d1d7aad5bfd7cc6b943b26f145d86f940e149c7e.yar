rule win_nexster_bot_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.nexster_bot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nexster_bot"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 52 e8???????? 68ff030000 8d85bd090000 }
		$sequence_1 = { ff15???????? 668985ae010000 6a10 8d85ac010000 50 57 }
		$sequence_2 = { 7d10 668b4c4310 66890c45186e4100 40 ebe8 33c0 }
		$sequence_3 = { 03f9 837d1810 7208 8b5d04 }
		$sequence_4 = { 33c0 8da42400000000 8a1485d0604100 889405000e0000 40 83f80b }
		$sequence_5 = { 731a 8bc8 83e01f c1f905 8b0c8d20804100 c1e006 03c1 }
		$sequence_6 = { 81c404040000 c3 53 56 57 8bf8 }
		$sequence_7 = { 66898c24bc010000 e9???????? 8b15???????? a1???????? 8b0d???????? 899424b0010000 }
		$sequence_8 = { 68???????? 52 e8???????? 68???????? 8d85bc110000 50 }
		$sequence_9 = { 8a08 40 84c9 75f9 8dbdbc150000 2bc6 4f }

	condition:
		7 of them and filesize <245760
}
