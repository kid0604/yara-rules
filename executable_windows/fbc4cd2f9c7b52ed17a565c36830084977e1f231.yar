rule win_ncctrojan_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.ncctrojan."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ncctrojan"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 68???????? e9???????? 83f801 750a 68???????? e9???????? 83f802 }
		$sequence_1 = { 83f805 7536 8b85e8feffff 85c0 750a 68???????? e9???????? }
		$sequence_2 = { 50 e8???????? 83c40c 8d842418050000 50 8d84247c460000 }
		$sequence_3 = { 6800400000 85c0 8d85ecbdffff 6a00 }
		$sequence_4 = { 50 e8???????? 83c410 8d4606 }
		$sequence_5 = { 8d85f4bfffff 6800400000 50 e8???????? 8d45f4 }
		$sequence_6 = { 84c0 75f9 eb47 e8???????? 68???????? }
		$sequence_7 = { 75f5 2bca d1f9 8d4101 50 e8???????? 8b542410 }
		$sequence_8 = { 8b8d70fffeff e9???????? 8d8d80fffeff e9???????? }
		$sequence_9 = { 837d1c10 8d4508 0f434508 50 ff15???????? }
		$sequence_10 = { 8b9580fffeff 8d5218 e8???????? 8d8578fffeff }
		$sequence_11 = { 50 ff15???????? 8b4518 8d4d08 }
		$sequence_12 = { 0f84b8000000 6a14 59 8bf3 8d7dac f3a5 }
		$sequence_13 = { 8b8a2cf8ffff 33c8 e8???????? 8b4afc 33c8 e8???????? b8???????? }
		$sequence_14 = { 837d1c10 8b7518 0f437d08 ff15???????? }
		$sequence_15 = { 50 51 8d4d08 e8???????? 56 }

	condition:
		7 of them and filesize <1160192
}
