rule win_retro_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.retro."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.retro"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 49ffcb 8941ec 418b440af0 8941f0 418b440af4 }
		$sequence_1 = { 8b442420 4863c8 ba04000000 e8???????? 4c8bb42478400000 4c8ba42480400000 488bb42488400000 }
		$sequence_2 = { 488b742468 488dab00120000 f30f100d???????? 4963c5 448b848308130000 418d4701 410fafc0 }
		$sequence_3 = { f30f58c2 f30f58c1 f30f58c5 4883c478 c3 660feb15???????? f30f5c15???????? }
		$sequence_4 = { f3410f1081f8550100 410f2fc0 7604 f30f59e8 8d442eff 4863c8 }
		$sequence_5 = { 418bd4 e8???????? 33c9 85c0 0f8514010000 4c8d2df2e70300 }
		$sequence_6 = { f30f59e8 418d4424ff 4863c8 483bcd 7c2e 0f1f00 660f6e0c8b }
		$sequence_7 = { 4881c460260000 415f 415e 415d 5f 5e 5b }
		$sequence_8 = { 48c1f905 4c8d05db7f0500 83e21f 486bd258 490314c8 488d0d79700200 eb11 }
		$sequence_9 = { f20f1035???????? 0f297c2430 0f57ff 33ff 83bab412000002 488bda 4c8bc9 }

	condition:
		7 of them and filesize <1409024
}
