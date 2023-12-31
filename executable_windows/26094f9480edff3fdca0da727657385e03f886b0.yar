rule win_royal_ransom_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.royal_ransom."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.royal_ransom"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 834f5404 488d05f53ee4ff 488b5c2430 488987b0020000 b801000000 4883c420 }
		$sequence_1 = { b820000000 e8???????? 482be0 488bda 488bf1 488bcb 488d15e89a1100 }
		$sequence_2 = { e8???????? 4c8d05dea70d00 ba2f010000 488d0df2a70d00 e8???????? 4533c0 baae000000 }
		$sequence_3 = { e8???????? 482be0 85d2 488d050ffe1600 488d3d14fe1600 418bd0 480f45f8 }
		$sequence_4 = { e8???????? 488bc8 4885c0 752f 41b920000000 488d0575010000 488d154e061400 }
		$sequence_5 = { 8bcf e9???????? 4c8b45e0 4533c9 488b55e8 e8???????? 488bf0 }
		$sequence_6 = { 448bf5 4d85ff 0f8502010000 e8???????? 4c8d05e0461400 ba27010000 488d0d84461400 }
		$sequence_7 = { 85c0 0f8531030000 4c396368 7527 e8???????? 4c8d05e11e1500 badc000000 }
		$sequence_8 = { 7534 4181e700000f00 74b6 4181ff00000100 0f8537ffffff 4c8d0da7e20a00 458bc4 }
		$sequence_9 = { e8???????? 4c8d053fd91300 bab7000000 488d0dfbd81300 e8???????? ba8c000000 4533c0 }

	condition:
		7 of them and filesize <6235136
}
