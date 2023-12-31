rule win_domino_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.domino."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.domino"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 418d6e0e 488d442420 8bcd c60000 }
		$sequence_1 = { 448bc0 e8???????? 3bc6 740a 488bcf }
		$sequence_2 = { 48ffc9 418a0409 8801 48ffca 75f2 }
		$sequence_3 = { 418bf8 8bf2 33db 488d4def }
		$sequence_4 = { 4885c0 7544 8b442450 4983c704 }
		$sequence_5 = { 488d4c2440 4533c9 4533c0 ba00000040 c744242002000000 ff15???????? }
		$sequence_6 = { 442bc7 4863c7 ffc7 4c8d542420 4488440420 4863c7 4963d0 }
		$sequence_7 = { 488bf8 ff15???????? 85c0 751e }
		$sequence_8 = { ff15???????? b001 eb02 32c0 4881c4e0000000 }
		$sequence_9 = { b806000000 e9???????? 4c63fd 41b900300000 33d2 488bc8 4d8bc7 }

	condition:
		7 of them and filesize <50176
}
