rule win_innaput_rat_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.innaput_rat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.innaput_rat"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff5708 56 ff5708 59 59 3b5d08 }
		$sequence_1 = { 394608 7721 8b06 894710 ff7604 035e08 }
		$sequence_2 = { 740e 68???????? 8d858cf9ffff 50 }
		$sequence_3 = { b001 ebd3 55 8bec }
		$sequence_4 = { 57 6800000100 e8???????? 6a02 }
		$sequence_5 = { 8b06 894710 ff7604 035e08 ff5708 56 ff5708 }
		$sequence_6 = { 035e08 ff5708 56 ff5708 }
		$sequence_7 = { 83f8ff 7404 3bc3 751b }
		$sequence_8 = { ff15???????? ffb718060000 ff15???????? 85c0 }
		$sequence_9 = { 391e 75fa 6a0c ff5704 59 }

	condition:
		7 of them and filesize <73728
}
