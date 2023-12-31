rule win_targetcompany_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.targetcompany."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.targetcompany"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0bc1 0bd6 b106 e8???????? 5e 894748 89574c }
		$sequence_1 = { 014de0 894df0 8b4de0 33ca 8b55f4 3355c4 c1c107 }
		$sequence_2 = { 85c0 7404 3b06 7405 e8???????? 3b5e04 }
		$sequence_3 = { 8b4508 53 56 57 8d9dc4dcffff 8985dcdcffff }
		$sequence_4 = { 014608 8b4658 11560c 014608 8b465c 8b4e54 11460c }
		$sequence_5 = { 99 8945f8 0fb64608 8bca 99 8b55f8 }
		$sequence_6 = { 7705 395808 7635 8db5e4dcffff e8???????? 8bf8 e8???????? }
		$sequence_7 = { 8bf8 85c0 74c7 83e900 740e 49 7553 }
		$sequence_8 = { 8d4de8 ffb5c4feffff ffb5c4feffff e8???????? 83c410 53 53 }
		$sequence_9 = { 895f14 3bc3 7454 e8???????? 3ac3 744b }

	condition:
		7 of them and filesize <328704
}
