rule win_fanny_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.fanny."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fanny"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff35???????? ffd6 e8???????? e8???????? e8???????? }
		$sequence_1 = { 83f8ff 740a 53 50 }
		$sequence_2 = { 53 eb0b 8b4704 83c708 }
		$sequence_3 = { 59 8bf0 59 33c9 3bf1 745c 8b542414 }
		$sequence_4 = { 55 8bec 837d0c00 742e 8b450c }
		$sequence_5 = { 8945d4 c745c400000000 8b4dc4 3b4dd0 7d26 }
		$sequence_6 = { c7460811000000 894604 8a0d???????? 50 884e10 ff75fc }
		$sequence_7 = { 8b742410 57 8b7c2410 56 57 e8???????? 83c408 }
		$sequence_8 = { ffd6 85c0 752b 397dfc 7526 8d45fc 8b3d???????? }
		$sequence_9 = { 8b4510 832000 33c0 e9???????? ff761c }
		$sequence_10 = { 885e15 897e11 380d???????? 750f 50 56 e8???????? }
		$sequence_11 = { 7417 8b4514 50 8b4d10 51 }
		$sequence_12 = { 53 50 6808100000 56 ffd7 fe45c6 8d55a8 }
		$sequence_13 = { c745b000000000 8d4dec e8???????? 8d4dd8 e8???????? 8b45b0 eb1a }
		$sequence_14 = { eb03 8b7508 8bc6 5f }
		$sequence_15 = { 68???????? 8b95ccfdffff 52 8b4508 50 ff15???????? 85c0 }

	condition:
		7 of them and filesize <368640
}
