rule win_grey_energy_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.grey_energy."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.grey_energy"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 50 53 53 6800000008 57 53 }
		$sequence_1 = { 8945cc e8???????? 68???????? 8945d4 e8???????? 68???????? 8945d0 }
		$sequence_2 = { 81e1ff000000 8b45ec 8b55f8 66890c42 eb14 }
		$sequence_3 = { 41 48 75f9 53 ff15???????? 8b75f8 }
		$sequence_4 = { 66890c42 eb14 8b45ec 8b4df8 8b55f0 8b7508 }
		$sequence_5 = { 0345f0 0fbe08 8b45f0 33d2 }
		$sequence_6 = { 8b45f0 8b4d08 0fb70c41 8b45f0 }
		$sequence_7 = { 8b55f0 8b7508 668b1456 66891441 }
		$sequence_8 = { 6a40 ff15???????? 8945f8 837df800 7507 33c0 e9???????? }
		$sequence_9 = { 8b45f8 0345ec 8808 eb10 }
		$sequence_10 = { 48 75fa 56 ff15???????? ff75f8 }
		$sequence_11 = { 7407 c60100 41 48 75f9 ff75f8 }
		$sequence_12 = { 51 e8???????? 85c0 0f84be000000 }
		$sequence_13 = { e8???????? 3bc3 740f 8b45fc 8b08 }
		$sequence_14 = { 56 e8???????? 8b75e4 3bf3 }
		$sequence_15 = { ff75dc ffd3 8b5db8 85db 7417 53 ffd6 }
		$sequence_16 = { 8b75fc 85f6 7417 56 ffd7 }
		$sequence_17 = { 3bfe 7c05 8975ec eb12 }

	condition:
		7 of them and filesize <303104
}
