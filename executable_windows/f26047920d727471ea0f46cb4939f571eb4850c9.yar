rule win_rcs_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.rcs."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rcs"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 5f 5e 5d 5b 33c0 }
		$sequence_1 = { 89442456 8944245a 8944245e 89442462 89442466 8944246a }
		$sequence_2 = { e8???????? 83c430 6aff 68???????? }
		$sequence_3 = { 85ff 0f84d4000000 57 e8???????? }
		$sequence_4 = { 6a00 6880000000 6a01 6a00 6a05 }
		$sequence_5 = { 40 68???????? 50 e8???????? 83c40c eb0d }
		$sequence_6 = { eb1e 8b8578f4fbff 8945f4 8945f0 8d45f0 50 6a08 }
		$sequence_7 = { 6a01 6a07 6a0c ff5660 eb12 8d85a4fafbff }
		$sequence_8 = { 8d8518fffbff 50 68a4000000 8b86dc000000 ffb06c020000 }
		$sequence_9 = { 397dfc 72a8 5f 5e 5b }
		$sequence_10 = { 81f11e49dc18 f8 33d9 f5 }
		$sequence_11 = { 833fff 750a b800000000 e9???????? 8b7d10 }
		$sequence_12 = { 81ec04020000 53 56 57 31ff 8b4508 }
		$sequence_13 = { 75f9 8b1d???????? 83c340 53 6a01 50 }
		$sequence_14 = { e9???????? c745e000000000 eb29 8b7de0 8b75f4 0fb73c7e 3b7dfc }
		$sequence_15 = { 81f11b2b5236 6685c3 f8 3af0 f7d9 }
		$sequence_16 = { 83f80f 763c 803953 7537 }
		$sequence_17 = { 83f80f 7575 33db 53 57 }

	condition:
		7 of them and filesize <11501568
}
