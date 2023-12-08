rule win_ddkong_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.ddkong."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ddkong"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b44241c 42 83c504 3bd0 72be 5f 5e }
		$sequence_1 = { c6458769 c6458874 c6458979 c6458a44 c6458b65 c6458c73 }
		$sequence_2 = { 6804000098 895dcc ff7508 c745d4e8030000 }
		$sequence_3 = { 3bc7 0f84b1000000 6a01 57 6a02 }
		$sequence_4 = { ffb524ffffff ff9560ffffff 834dfcff e8???????? ff957cffffff 8b4df0 }
		$sequence_5 = { 7304 8bc3 eb66 8d45fc }
		$sequence_6 = { 50 53 c645d447 c645d565 c645d674 c645d743 c645d875 }
		$sequence_7 = { c645c441 ffd7 50 ffd6 8065e800 8b3d???????? 8d45dc }
		$sequence_8 = { ffb540ffffff ffb5b8feffff 56 56 56 ff7510 ff750c }
		$sequence_9 = { c645966e c6459774 c6459865 c6459972 8d458c }

	condition:
		7 of them and filesize <81920
}
