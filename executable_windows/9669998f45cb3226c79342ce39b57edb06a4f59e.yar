rule win_jlorat_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.jlorat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.jlorat"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 660f6f8424f0030000 0f298424d0010000 0f28842450020000 0f288c24d0010000 0f289424c0010000 660f7f942410040000 }
		$sequence_1 = { f20f1101 8b4de8 64890d00000000 83c474 5e 5f 5b }
		$sequence_2 = { e8???????? 89442440 8b442440 83c008 89442430 c744244400000000 8b4c2444 }
		$sequence_3 = { c74008???????? c7400421000000 c700???????? e8???????? 0f0b 8b4c2438 8b44245c }
		$sequence_4 = { e8???????? eb21 c745f008000000 89e0 8d8d60ffffff 894804 8d8d74ffffff }
		$sequence_5 = { eb80 8b2c24 83fb0a 83df00 733f 8b54242c 8b742404 }
		$sequence_6 = { eb00 8b45b4 8b4db8 c645e201 894dc4 c645e101 8945c8 }
		$sequence_7 = { f7e1 89c1 8a842417010000 01f2 89942418010000 0f92c4 08e0 }
		$sequence_8 = { eb00 f645d901 0f854e030000 e9???????? 8a8583feffff a801 7553 }
		$sequence_9 = { 8b8ea0030000 8b86a4030000 898e000c0000 8986040c0000 8b86840a0000 89465c 8b86000c0000 }

	condition:
		7 of them and filesize <10952704
}
