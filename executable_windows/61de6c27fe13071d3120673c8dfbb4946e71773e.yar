rule win_blackbyte_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.blackbyte."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackbyte"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 488d4101 0f1f8000000000 4883f85b 0f8dc0000000 }
		$sequence_1 = { 0bd1 8b4c244c 4103cf 450fb67b17 33d1 }
		$sequence_2 = { 488d0db4030000 488908 833d????????00 7520 }
		$sequence_3 = { 39580c 7516 44387ddf 740b 488b45c7 83a0a8030000fd 448bcb }
		$sequence_4 = { 488d5301 488b5c2468 488b742440 488b7c2448 }
		$sequence_5 = { 0bd9 410fb64b28 450fb65b2f 41c1e308 }
		$sequence_6 = { 397574 0f85ad000000 8b4570 4c8d4d58 }
		$sequence_7 = { 488d442448 488d5c2438 31c9 31ff be02000000 }
		$sequence_8 = { 39742478 0f8496000000 4883cdff 4c8bf5 }
		$sequence_9 = { 0f28bc2490020000 0f28b424a0020000 4c8bb424b0020000 488bb424e0020000 }
		$sequence_10 = { 488d4b07 4889c3 488d442460 e8???????? }
		$sequence_11 = { 396b68 0f8639010000 4889742448 48897c2450 }
		$sequence_12 = { 488d0de5000000 488908 833d????????00 751d }
		$sequence_13 = { 488d5c241d b911000000 e8???????? 488b6c2440 4883c448 c3 89f0 }
		$sequence_14 = { 488d1592020000 4889542458 48894c2460 488d4c2458 }
		$sequence_15 = { 0bd9 410fb64b29 c1e308 0bd9 }

	condition:
		7 of them and filesize <9435136
}
