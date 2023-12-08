rule win_trochilus_rat_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.trochilus_rat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.trochilus_rat"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { f7f9 885614 e8???????? 99 f7ff 8b4508 894616 }
		$sequence_1 = { ff750c ff7508 50 ff15???????? 8b4d10 8901 }
		$sequence_2 = { 41 894808 83f908 72e2 8b4808 89048dc47b8100 8b4008 }
		$sequence_3 = { e8???????? 8bf8 85ff 7414 8b06 6a01 8bce }
		$sequence_4 = { 8bce e8???????? ff45ec e9???????? 0fb74738 8b1d???????? 50 }
		$sequence_5 = { 8b460c 99 014708 bee81d0110 11570c 8b03 }
		$sequence_6 = { e8???????? 6a38 8d8568f3ffff 57 50 c78564f3ffff3c000000 e8???????? }
		$sequence_7 = { 6a5b 68???????? 6a00 e8???????? 83c414 33c0 }
		$sequence_8 = { 6880000110 e8???????? 33d2 8955e4 8b4510 8b4804 3bca }
		$sequence_9 = { ff37 83c615 50 56 e8???????? 83c428 6a04 }

	condition:
		7 of them and filesize <630784
}
