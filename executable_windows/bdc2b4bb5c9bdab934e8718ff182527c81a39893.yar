rule win_former_first_rat_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.former_first_rat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.former_first_rat"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c78500ffffff00100000 89b5e8feffff e8???????? 8bd8 83c404 899df0feffff 3bde }
		$sequence_1 = { e8???????? 83c408 3bc3 7510 56 68???????? }
		$sequence_2 = { 50 ff15???????? 8b4d10 8b55e8 6a00 51 }
		$sequence_3 = { 66890c02 83c002 6685c9 75f1 8d85e0fdffff }
		$sequence_4 = { 6a00 8d8dfceeffff 51 6800100000 8d95f4efffff 52 50 }
		$sequence_5 = { 68???????? e8???????? 8b0d???????? 2b0d???????? b87fe0077e f7e9 }
		$sequence_6 = { 8b4de8 8b45f0 8b55ec 898db0fbffff }
		$sequence_7 = { 8b742438 8b06 8d4804 89442414 8b442430 }
		$sequence_8 = { 03c2 83e003 3bc2 7516 418bc2 }
		$sequence_9 = { 03ca 0fb6c9 428a1401 4130143b }
		$sequence_10 = { 02ca 4402d1 410fb6ca 42321401 }
		$sequence_11 = { 03c1 89442468 413bc5 7250 }
		$sequence_12 = { 03cf 8908 488b4340 48833800 }
		$sequence_13 = { 02c8 488d05f0f60100 02c9 4002ce }
		$sequence_14 = { 017130 83793005 7407 33c0 }
		$sequence_15 = { 03cd 8908 f6437804 7417 }

	condition:
		7 of them and filesize <626688
}
