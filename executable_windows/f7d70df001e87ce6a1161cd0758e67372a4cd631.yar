rule win_dustman_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.dustman."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dustman"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 488d1566a10000 488d0d57a10000 e8???????? 488b4308 833800 750e }
		$sequence_1 = { 884824 488b4d28 0fb60c01 884825 488b4d30 }
		$sequence_2 = { 4903cb 48898df0000000 488bca 492bca 4c8d9ddf010000 }
		$sequence_3 = { 4c8d0df1820000 488bd9 488d15e7820000 b916000000 4c8d05d3820000 e8???????? }
		$sequence_4 = { c5f1eb0d???????? 4c8d0d36850000 c5f35cca c4c173590cc1 4c8d0d05750000 }
		$sequence_5 = { 782e 3b0d???????? 7326 4863c9 488d153cde0000 488bc1 83e13f }
		$sequence_6 = { 48898d18010000 488bca 492bca 4c8d9de4010000 4903cb 48898d20010000 488bca }
		$sequence_7 = { 4156 4157 4883ec20 488b6918 4d8bf0 488bf9 4c3bc5 }
		$sequence_8 = { 4c8d9db3010000 4903cb 48894d98 488bca 492bca }
		$sequence_9 = { e8???????? 85c0 0f8403010000 488d0586e10000 4a8b04e8 }

	condition:
		7 of them and filesize <368640
}
