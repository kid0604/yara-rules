rule win_scarabey_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.scarabey."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.scarabey"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 75d0 8d8df4fcffff c645fc00 c785f4fcffffa42d5300 e8???????? 834dfcff }
		$sequence_1 = { 83f808 0f876e010000 53 ff248516094f00 33db eb10 33db }
		$sequence_2 = { 8b03 3b70f8 7fbd 8970f4 8b03 5d 5f }
		$sequence_3 = { c745d878025300 e8???????? e8???????? c22000 6a10 }
		$sequence_4 = { 85c0 7906 d805???????? 83ec08 dd1c24 e8???????? 8b0d???????? }
		$sequence_5 = { 6a10 e8???????? 83c404 85c0 742a 8b4e04 8904b9 }
		$sequence_6 = { ffd7 56 ffd7 8b85f4d6ffff 50 }
		$sequence_7 = { 898524d7ffff ffd3 8b9524d7ffff 682000cc00 6807080000 6a00 6a00 }
		$sequence_8 = { c745ec60e05300 e8???????? 8bd8 895df0 893d???????? 8b8e200e0000 ff7508 }
		$sequence_9 = { 8985d8d6ffff db85d8d6ffff 7906 dc05???????? dd9d38d6ffff }

	condition:
		7 of them and filesize <3580928
}
