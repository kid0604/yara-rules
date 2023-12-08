rule win_nabucur_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.nabucur."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nabucur"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 48 894500 85c0 7fee }
		$sequence_1 = { 009eaa030000 0fb686aa030000 57 83f80a 0f876d010000 }
		$sequence_2 = { 49 23ce 894f18 8bf0 85c0 0f8521040000 }
		$sequence_3 = { 48 8944241c 85c0 7fd1 }
		$sequence_4 = { 49 23cb 894d08 5d }
		$sequence_5 = { 33ff 33f6 4a c744244001000000 89542434 8b6c2438 895c2430 }
		$sequence_6 = { 49 23cf 894c241c 3bc3 }
		$sequence_7 = { 49 03d3 40 85c9 }
		$sequence_8 = { bb174449fd e9???????? 46 49 e9???????? }
		$sequence_9 = { 5e e9???????? 5e e9???????? 6851b6940c }
		$sequence_10 = { 66833800 740b 83c102 81f980000000 75e3 8d45fc }
		$sequence_11 = { bb4eed56fd ebdd 83e904 ebeb 83c604 ebf6 }
		$sequence_12 = { bb76f4e0fc 3106 ba92ace0fe ebb3 83f905 7df2 }
		$sequence_13 = { b6e3 086970 dea3e1395fe7 763c de20 ad }
		$sequence_14 = { 5e a2???????? e631 319aea073790 e033 3394e43f06c3b1 }
		$sequence_15 = { e9???????? 83e904 ebb2 49 }

	condition:
		7 of them and filesize <1949696
}
