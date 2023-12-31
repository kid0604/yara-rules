rule win_koobface_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.koobface."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.koobface"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 3bc3 0f8410010000 8b08 8d55e4 52 68???????? 53 }
		$sequence_1 = { 8b8dd0fdffff 8d852cfeffff 50 c745fc33000000 e8???????? 56 }
		$sequence_2 = { a5 83ec10 8bfc 8db590fbffff a5 a5 }
		$sequence_3 = { 8d044554494200 8bc8 2bce 6a03 }
		$sequence_4 = { 8bf8 59 59 3bfb 7508 8bbd0cfeffff }
		$sequence_5 = { 8b45e8 8b08 53 50 }
		$sequence_6 = { 50 c645fc1c e8???????? 56 8945b4 }
		$sequence_7 = { 0355f0 8dbc3a05e9e3a9 c1c705 037db0 8bd0 897db8 f7d2 }
		$sequence_8 = { 5d c20400 c3 56 68???????? 8bf1 e8???????? }
		$sequence_9 = { e9???????? 8d4df0 e9???????? 8d4d10 e9???????? 8d4de8 e9???????? }

	condition:
		7 of them and filesize <368640
}
