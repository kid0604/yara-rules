rule win_greenshaitan_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.greenshaitan."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.greenshaitan"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c644246001 e8???????? 837c242c10 720d 8b542418 52 e8???????? }
		$sequence_1 = { c70200000000 e8???????? 8b4c2434 83c404 837b2400 8901 }
		$sequence_2 = { 8bd9 33f6 895c2414 c78424940000000f000000 89b42490000000 c684248000000000 6a04 }
		$sequence_3 = { 51 52 8d7c243c e8???????? 8b44244c 83c424 5f }
		$sequence_4 = { 8d442418 89542418 897c241c e8???????? 8b00 8b4d08 394808 }
		$sequence_5 = { e8???????? 83c404 33c0 c746340f000000 894630 8d4e04 884620 }
		$sequence_6 = { 5e 5b 59 c3 83c004 51 50 }
		$sequence_7 = { b9???????? 8bf8 e8???????? 84c0 742e 83fb03 7e29 }
		$sequence_8 = { 7509 8b44241c 897834 eb4f 83fe02 7304 }
		$sequence_9 = { 8d842490000000 64a300000000 8bf9 33db }

	condition:
		7 of them and filesize <253952
}
