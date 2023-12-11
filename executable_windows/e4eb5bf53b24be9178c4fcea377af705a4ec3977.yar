rule win_fishmaster_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.fishmaster."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fishmaster"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 66c704083d00 e9???????? 48c744242001000000 ba01000000 488bcb e8???????? }
		$sequence_1 = { 488b542440 7209 488d4206 4903c1 eb12 488d4c2440 488d442446 }
		$sequence_2 = { 4180f82f 410f44ff c1ff02 c0e204 400afa }
		$sequence_3 = { c7450000020000 c745c000020000 c745f000020000 c745d000020000 c7451000020000 }
		$sequence_4 = { e8???????? 488bd8 448b8550200000 33d2 }
		$sequence_5 = { 724a 488b1e 488bd3 e8???????? }
		$sequence_6 = { 488d054d2a0000 c3 8325????????00 c3 48895c2408 55 }
		$sequence_7 = { 418d5601 33c9 ff15???????? c7855820000004000000 4489b540200000 4533c9 440fb745d4 }
		$sequence_8 = { 4c897530 48c745380f000000 44887520 488d8580000000 49c7c0ffffffff 49ffc0 46383400 }
		$sequence_9 = { 8d71b9 eb1c 8d41d0 3c09 }

	condition:
		7 of them and filesize <812032
}
