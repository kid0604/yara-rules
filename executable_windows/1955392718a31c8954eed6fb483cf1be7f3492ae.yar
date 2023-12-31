rule win_adylkuzz_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.adylkuzz."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.adylkuzz"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e9???????? 0fb74702 ba93100000 8b742418 0fb70446 890424 e9???????? }
		$sequence_1 = { fec9 668b4c2502 81ed02000000 6603c1 6689442504 0f43c2 9c }
		$sequence_2 = { f8 35a6348e03 33d8 66f7c4323b 6685e5 03f8 57 }
		$sequence_3 = { e9???????? 8b4c2500 c0e254 8b542504 13c6 66d3f0 81c504000000 }
		$sequence_4 = { eb10 8d4306 89442410 0fb74306 e9???????? 83c42c 89f1 }
		$sequence_5 = { d1e9 f3ab 13c9 f366ab f7c7bb6a161a 660fabdf 1bf8 }
		$sequence_6 = { 89442420 8b4310 29442420 c17c242003 c744240401000000 891c24 e8???????? }
		$sequence_7 = { ed 6abe fc b2d7 ac 2a52b5 226842 }
		$sequence_8 = { e8???????? 85c0 52 8903 7509 8b5dfc c9 }
		$sequence_9 = { e8???????? 89f1 89f7 c1e908 83e77f c1ee10 83e17f }

	condition:
		7 of them and filesize <6438912
}
