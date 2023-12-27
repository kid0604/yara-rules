rule win_gearshift_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.gearshift."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gearshift"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 498bd4 488bcb ff15???????? 41b900800000 41b810010000 }
		$sequence_1 = { 6689442455 88442457 8885f0000000 e8???????? 33d2 488d8d81000000 }
		$sequence_2 = { 0f84ec000000 8bc8 48034d08 ff96c0000000 4c8be0 4883f8ff 0f841d020000 }
		$sequence_3 = { ff15???????? 488d1587ae0000 498bcc 48894528 ff15???????? 488d1563af0000 498bcc }
		$sequence_4 = { 488b88c0000000 488d05a73b0300 395914 4a8b0ce0 498b0c0f 0f94c3 ff15???????? }
		$sequence_5 = { 75b6 488bcd ff15???????? 4c8bac2478010000 488bbc2470010000 }
		$sequence_6 = { 48897818 488b05???????? 4833c4 48894570 488d0d5f320200 }
		$sequence_7 = { 488b742410 488b7c2418 c3 41ffc2 48ffc2 443bd3 }
		$sequence_8 = { 448ba890000000 ba14000000 4c036d08 498bcd }
		$sequence_9 = { 0fb7d1 eb09 488b4508 488d540102 }

	condition:
		7 of them and filesize <540672
}