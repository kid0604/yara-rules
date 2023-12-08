rule win_polyglot_ransom_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.polyglot_ransom."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.polyglot_ransom"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff7510 e8???????? 59 8945f4 eb03 8975f4 53 }
		$sequence_1 = { 50 ff35???????? ff15???????? ff35???????? ff15???????? 5e 8b4dfc }
		$sequence_2 = { 68c0160000 51 ff7628 ff5620 8bf8 83c40c 85ff }
		$sequence_3 = { e8???????? 8d8560080000 50 8d8518060000 56 50 e8???????? }
		$sequence_4 = { be20d0b2d1 80d0b5 d0bcd18f20d0b2 d0bed181d181 d182d0b0d0bd d0bed0b2d0bb d0b5d0bdd0b8 }
		$sequence_5 = { 82d18c 3c2f 61 3e0d0a3c6120 636c6173 733d 226275 }
		$sequence_6 = { 8bc6 e8???????? 85c0 59 59 7403 83cfff }
		$sequence_7 = { e8???????? 84c0 740e 57 8bce e8???????? 8be8 }
		$sequence_8 = { 8b06 8bc8 c1f905 8b0c8d809b4800 83e01f c1e006 8d440124 }
		$sequence_9 = { 5e 5b 7402 8907 85c0 74a4 837d1000 }

	condition:
		7 of them and filesize <1392640
}
