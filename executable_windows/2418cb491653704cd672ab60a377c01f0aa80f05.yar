rule win_amadey_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.amadey."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.amadey"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ebb0 b8???????? 83c410 5b }
		$sequence_1 = { e8???????? 89c2 8b45f4 89d1 ba00000000 f7f1 }
		$sequence_2 = { c744240805000000 c744240402000000 890424 e8???????? }
		$sequence_3 = { c9 c3 55 89e5 81ecc8010000 }
		$sequence_4 = { c70424???????? e8???????? 8b45fc 89442408 c7442404???????? 8b4508 890424 }
		$sequence_5 = { c744240800020000 8d85f8fdffff 89442404 891424 e8???????? 83ec20 }
		$sequence_6 = { c70424???????? e8???????? 890424 e8???????? 84c0 7407 c745fc05000000 }
		$sequence_7 = { 83ec04 8945f4 837df400 7454 8b4508 890424 }
		$sequence_8 = { 83fa10 722f 8b8d78feffff 42 }
		$sequence_9 = { 8b8d78feffff 42 8bc1 81fa00100000 7214 8b49fc }
		$sequence_10 = { 68???????? e8???????? 8d4dcc e8???????? 83c418 }
		$sequence_11 = { 68???????? e8???????? 8d4db4 e8???????? 83c418 }
		$sequence_12 = { 52 6a02 6a00 51 ff75f8 ff15???????? ff75f8 }
		$sequence_13 = { 8bce e8???????? e8???????? 83c418 e8???????? e9???????? 52 }
		$sequence_14 = { c705????????0c000000 eb31 c705????????0d000000 eb25 83f901 750c }
		$sequence_15 = { 50 68???????? 83ec18 8bcc 68???????? e8???????? }
		$sequence_16 = { 8bcc 68???????? e8???????? 8d8d78feffff e8???????? 83c418 }
		$sequence_17 = { c78584fdffff0f000000 c68570fdffff00 83fa10 722f 8b8d58fdffff 42 }
		$sequence_18 = { c78520fdffff00000000 c78524fdffff0f000000 c68510fdffff00 83fa10 722f }
		$sequence_19 = { 51 e8???????? 83c408 8b950cfdffff c78520fdffff00000000 c78524fdffff0f000000 }

	condition:
		7 of them and filesize <529408
}