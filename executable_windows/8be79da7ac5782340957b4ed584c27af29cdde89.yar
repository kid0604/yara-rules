rule win_stuxnet_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.stuxnet."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.stuxnet"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 3d02010000 7504 32c0 ebe2 8bb600010000 3bc6 }
		$sequence_1 = { c645fc01 8b450c 2bc3 742e 48 755a e8???????? }
		$sequence_2 = { ff15???????? 8906 8bc6 c3 ff30 ff15???????? c3 }
		$sequence_3 = { e8???????? 885dfc 8d45c0 50 e8???????? 8d45e4 50 }
		$sequence_4 = { ebf5 55 8bec 81ec14040000 56 33f6 8d85ecfbffff }
		$sequence_5 = { e8???????? 33db 895dfc 6a04 e8???????? 59 c645fc01 }
		$sequence_6 = { e8???????? 8b4df4 64890d00000000 c9 c20400 8b4604 8d4e0c }
		$sequence_7 = { c3 b8???????? e9???????? 8d456c e9???????? 8d7548 e9???????? }
		$sequence_8 = { c6460c00 e8???????? 59 59 c645fc01 8b5804 834804ff }
		$sequence_9 = { ffd6 83f802 74e8 8d75f4 e8???????? 68???????? 8bc6 }

	condition:
		7 of them and filesize <2495488
}
