rule win_amadey_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.amadey."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.amadey"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8945f4 837df408 744f 8d85e8fdffff 890424 e8???????? c70424???????? }
		$sequence_1 = { c745fc00000000 e8???????? 84c0 750c c7042401000000 e8???????? e8???????? }
		$sequence_2 = { 89442404 891424 e8???????? 85c0 7510 8b45fc 40 }
		$sequence_3 = { 890424 e8???????? c7042400000000 e8???????? 81c424040000 }
		$sequence_4 = { e8???????? 8945f4 837df40a 0f842e010000 }
		$sequence_5 = { e8???????? c7442404???????? 8b4508 890424 e8???????? 85c0 7e75 }
		$sequence_6 = { 890424 e8???????? c7042401000000 e8???????? 89442404 8d85e8fbffff 890424 }
		$sequence_7 = { e8???????? 8b4508 c60000 c9 }
		$sequence_8 = { 68???????? e8???????? 8d4dcc e8???????? 83c418 }
		$sequence_9 = { 83fa10 722f 8b8d78feffff 42 8bc1 81fa00100000 7214 }
		$sequence_10 = { 52 51 e8???????? 83c408 8b955cfeffff }
		$sequence_11 = { 50 68???????? 83ec18 8bcc 68???????? }
		$sequence_12 = { 8b7dfc 8d4201 3bcb 7ccb 837e1410 }
		$sequence_13 = { 83c408 8b554c c7453000000000 c745340f000000 c6452000 83fa10 0f8204ffffff }
		$sequence_14 = { 68e8030000 ff15???????? 8b551c 83fa10 7228 8b4d08 }
		$sequence_15 = { 83fa10 722f 8b8d60feffff 42 }
		$sequence_16 = { 68???????? e8???????? 8d4db4 e8???????? 83c418 }
		$sequence_17 = { c78514feffff0f000000 c68500feffff00 83fa10 722f 8b8de8fdffff 42 }
		$sequence_18 = { 83c408 8b95fcfdffff c78510feffff00000000 c78514feffff0f000000 c68500feffff00 83fa10 }

	condition:
		7 of them and filesize <520192
}
