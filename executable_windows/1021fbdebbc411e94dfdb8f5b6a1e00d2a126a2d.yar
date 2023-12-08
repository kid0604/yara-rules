rule win_mimic_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.mimic."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mimic"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? c645fc18 8d8d8cfeffff ff30 e8???????? 8d8d3cfeffff c645fc1a }
		$sequence_1 = { 83f805 0f8778010000 ff2485342a4800 68ad000000 68???????? 6a6c }
		$sequence_2 = { e8???????? ff74245c e8???????? 83c408 894610 837e0800 0f84fcfdffff }
		$sequence_3 = { 0fb74202 50 e8???????? 83c404 84c0 7438 0fb74204 }
		$sequence_4 = { ff35???????? ffd3 89442414 85c0 74e9 6800800000 56 }
		$sequence_5 = { ff75e4 8d8dd4feffff e8???????? 8d55e4 8d8de0fdffff e8???????? 8d8de0fdffff }
		$sequence_6 = { ff7634 ffd3 ff7638 ffd3 8b3d???????? c7462c00000000 c7463000000000 }
		$sequence_7 = { ff36 8d442474 6800040000 50 e8???????? 83c40c 8d442470 }
		$sequence_8 = { 8985dcfffeff 8b85e0fffeff 8985ecfffeff 80bdd4fffeff00 0f84bd000000 e8???????? 8bd8 }
		$sequence_9 = { ffb530feffff e8???????? c645fc08 83c408 8b8d1cfeffff 85c9 7430 }

	condition:
		7 of them and filesize <4204544
}
