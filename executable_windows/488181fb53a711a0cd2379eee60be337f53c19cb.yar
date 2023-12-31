rule win_wonknu_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.wonknu."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wonknu"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6a04 50 ff15???????? 68???????? }
		$sequence_1 = { b901050000 f3a5 8bcb e8???????? }
		$sequence_2 = { b901050000 f3a5 8bcb e8???????? 803b00 }
		$sequence_3 = { 8bfc b901050000 f3a5 8bcb }
		$sequence_4 = { eb08 c6840550ffffff00 8d8550ffffff 50 e8???????? }
		$sequence_5 = { eb08 c6840550ffffff00 8d8550ffffff 50 }
		$sequence_6 = { e8???????? 8bfc b901050000 f3a5 8bcb e8???????? }
		$sequence_7 = { e8???????? 8bfc b901050000 f3a5 8bcb e8???????? 803b00 }
		$sequence_8 = { 8bfc b901050000 f3a5 8bcb e8???????? }
		$sequence_9 = { f3a5 8bcb e8???????? 803b00 }

	condition:
		7 of them and filesize <540672
}
