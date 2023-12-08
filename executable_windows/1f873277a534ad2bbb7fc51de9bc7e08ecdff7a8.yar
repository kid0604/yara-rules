rule win_socksbot_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.socksbot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.socksbot"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 75e9 5f 5b 8bc2 5e }
		$sequence_1 = { 56 6a50 ff7508 33f6 8975fc e8???????? 8bd8 }
		$sequence_2 = { 8d85bcfeffff 50 ff15???????? 40 }
		$sequence_3 = { 89759c ff15???????? 85c0 7507 32c0 e9???????? }
		$sequence_4 = { 8b35???????? 57 ffd6 6a00 ff75f8 8bf8 }
		$sequence_5 = { 59 59 85f6 7e1c 33c0 50 }
		$sequence_6 = { 85c0 7564 8b45fc 33f6 8b08 }
		$sequence_7 = { 7550 ff758c e8???????? 8bd8 59 85db 7441 }
		$sequence_8 = { 890d???????? a3???????? 5e c9 c3 55 }
		$sequence_9 = { e8???????? 83c40c c6443dd000 8b7df8 }

	condition:
		7 of them and filesize <73728
}
