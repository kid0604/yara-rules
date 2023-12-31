rule win_meterpreter_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.meterpreter."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.meterpreter"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 55 8bec dcec 088b55895356 108b3a85ff89 7dfc 750e }
		$sequence_1 = { fc b8c0150000 8b7508 33e5 257e040275 238b1d6a016a 006a00 }
		$sequence_2 = { f1 57 52 bc40e84fff 38ff 83db14 5f }
		$sequence_3 = { 314319 034319 83ebfc 0acb }
		$sequence_4 = { 0000 68ffff0000 52 ffd7 8b2410 }
		$sequence_5 = { 8be5 5d c27f00 8d4df4 8d55ec }
		$sequence_6 = { 51 6a00 6a00 37 0052bf 15???????? 85c0 }
		$sequence_7 = { 8b451c 8d07 a4 52 8d4d18 50 }
		$sequence_8 = { 41 00ff 15???????? 33c0 c3 7790 55 }
		$sequence_9 = { 83ec08 53 8b4708 57 33ff 85db }

	condition:
		7 of them and filesize <188416
}
