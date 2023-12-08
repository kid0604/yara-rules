rule win_danabot_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.danabot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.danabot"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b4500 50 8b44241c 50 6a06 }
		$sequence_1 = { 6a01 53 ff15???????? 85c0 0f84ed000000 }
		$sequence_2 = { 50 8b442428 50 6a0e 68870dd5f4 8bc7 }
		$sequence_3 = { e8???????? 85c0 0f84adfbffff c3 85d2 }
		$sequence_4 = { 8bd9 85db 780a c1eb02 8b349a 4b 56 }
		$sequence_5 = { 68f87ca21f 8bc7 8b0b 8b5500 e8???????? 8b03 }
		$sequence_6 = { 3b85d0feffff 7452 8b85d0feffff 50 6a00 }
		$sequence_7 = { 8b55f4 8d45f8 e8???????? 8b55f8 8bc7 }
		$sequence_8 = { 6a01 ff15???????? 85c0 743b 8b45f0 50 }
		$sequence_9 = { 8bde 85db 7405 83eb04 }

	condition:
		7 of them and filesize <237568
}
