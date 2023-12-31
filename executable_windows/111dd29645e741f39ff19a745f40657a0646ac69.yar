rule win_yoddos_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.yoddos."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.yoddos"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b4d08 ff4508 397d08 88840dbcf3ffff 7ce4 8d85bcf3ffff 57 }
		$sequence_1 = { ffd7 50 ffd6 898538ffffff 899d50ffffff 899d3cffffff c68554ffffff4d }
		$sequence_2 = { 50 8d85b4fdffff 50 ff15???????? 8b3d???????? 8d45bc 50 }
		$sequence_3 = { 6a04 50 8d85c0f7ffff 50 e8???????? 8d45fc 6a01 }
		$sequence_4 = { 53 50 57 53 53 ff55f0 83bd34ffffff02 }
		$sequence_5 = { ffd6 898528ffffff c645c043 c645c16c c645c26f c645c373 c645c465 }
		$sequence_6 = { 8d8550feffff 68???????? 50 e8???????? 83c410 3bc3 740c }
		$sequence_7 = { 8bec 81ec2c010000 57 b863000000 90 b89dffffff 90 }
		$sequence_8 = { 8b3d???????? 53 ffb510ffffff 68???????? 53 53 ffd7 }
		$sequence_9 = { 8d854cfdffff 50 e8???????? 56 ff7508 8d854cfdffff 50 }

	condition:
		7 of them and filesize <557056
}
