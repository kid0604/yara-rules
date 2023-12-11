rule win_unidentified_076_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.unidentified_076."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_076"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 488b4618 48897858 488b4618 48894050 488b4e18 4863414c 4803c1 }
		$sequence_1 = { 498bd7 89442428 895c2420 41ff9240030000 85c0 7926 }
		$sequence_2 = { 483b3f 75d4 488dbb88000000 eb27 488b17 488b0a }
		$sequence_3 = { 8bef e9???????? 4180ff51 0f8541010000 }
		$sequence_4 = { 443be3 0f8c3effffff 33c0 488b5c2450 488b6c2458 }
		$sequence_5 = { 488b87c8000000 8b9068050000 ebb6 4c8b06 488b8f68020000 41b900008000 ba0e660000 }
		$sequence_6 = { 0f85ab000000 4533ff 4c8bf7 8d7001 4885ff 0f84af000000 4183ff14 }
		$sequence_7 = { 448b434c 443b4374 7837 b9581b0000 394b78 }
		$sequence_8 = { 4885ff 7472 488b86c8000000 33d2 488bcf 448d4220 ff9020070000 }
		$sequence_9 = { 488bcb e8???????? 488bcb e8???????? 488bcb 85c0 751e }

	condition:
		7 of them and filesize <114688
}
