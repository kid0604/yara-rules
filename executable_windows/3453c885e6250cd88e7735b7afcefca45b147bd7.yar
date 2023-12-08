rule win_neutrino_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.neutrino."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.neutrino"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? c1e010 50 ff15???????? }
		$sequence_1 = { 50 6a05 6a03 e8???????? }
		$sequence_2 = { 50 6a0b 6a07 e8???????? }
		$sequence_3 = { 8955fc 8b45fc 0fbe08 85c9 741b 8b55fc 0fbe02 }
		$sequence_4 = { 8945f4 8b4d0c 894dfc 8b55f4 0fbe02 85c0 7447 }
		$sequence_5 = { 6a00 e8???????? 83c40c 0fb6c0 }
		$sequence_6 = { 83c201 8955f8 8b45f8 0fbe08 85c9 7439 8b550c }
		$sequence_7 = { 8b4508 0fb608 51 e8???????? 83c404 0fb6d0 83fa01 }
		$sequence_8 = { 0404 010404 0202 020402 0404 0404 }
		$sequence_9 = { 8b55fc 0fbe02 85c0 750f 8b4d0c 894dfc }
		$sequence_10 = { e9???????? 6a01 ff15???????? 85c0 }
		$sequence_11 = { 0fb655e7 52 8b45e0 50 e8???????? }
		$sequence_12 = { 6a00 ff15???????? 6880000000 ff15???????? }
		$sequence_13 = { 0404 0404 010404 0202 }
		$sequence_14 = { 0404 0404 0404 0404 0404 0402 0202 }
		$sequence_15 = { 8b4d0c 894dfc 8b55f4 83c201 8955f4 ebaf 8b45f4 }
		$sequence_16 = { 7502 eb02 ebb4 8b45f8 8945f4 8b4d0c 894dfc }
		$sequence_17 = { 59 bb???????? 8bfa 32c0 c645ff00 895dec c645fb00 }
		$sequence_18 = { 83c120 81fae00f0000 76ea 8b0d???????? 8908 a3???????? 5f }
		$sequence_19 = { 51 ff35???????? c7460480000000 ff15???????? 8906 85c0 }
		$sequence_20 = { 66894210 83c302 f645fe02 740a 834a1804 8a03 }
		$sequence_21 = { 894210 83c304 eb13 f645fe20 740d 814a1804010000 }
		$sequence_22 = { 0f879a000000 807dfd01 0f8597000000 e9???????? 2d8c000000 747e 48 }
		$sequence_23 = { 895dec c645fb00 f3aa c645f810 56 8b45f4 8a00 }
		$sequence_24 = { 7354 8b3b 0fb6f2 6a05 58 2bc6 }
		$sequence_25 = { 83c404 85c0 0f95c2 0fb6c2 50 }
		$sequence_26 = { 8d85b8feffff 50 68???????? ff15???????? }
		$sequence_27 = { 83c40c 6804010000 8d85f8fdffff 50 }
		$sequence_28 = { 50 ff15???????? 837dfc00 0f95c0 c9 c3 }
		$sequence_29 = { 8906 ff15???????? 83c604 83c703 81fe???????? 7ce3 }
		$sequence_30 = { 57 33ff 393d???????? 7522 be???????? }
		$sequence_31 = { be???????? ff15???????? 57 8906 ff15???????? }
		$sequence_32 = { ff7508 ff15???????? 83f8ff 0f95c0 5d }
		$sequence_33 = { 85c0 7412 68???????? 50 ff15???????? f7d8 }

	condition:
		7 of them and filesize <507904
}
