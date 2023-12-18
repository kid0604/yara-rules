rule win_taurus_stealer_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.taurus_stealer."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.taurus_stealer"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 56 8b7508 eb12 8d4e1c e8???????? 8bce e8???????? }
		$sequence_1 = { 8d4de8 e8???????? 85f6 7408 8d4dd0 e8???????? 8b4508 }
		$sequence_2 = { 88550f 88450e 8d450e 51 50 8d4d8c e8???????? }
		$sequence_3 = { 51 50 8bce e8???????? 8d4dcc e8???????? 8d4db4 }
		$sequence_4 = { 7305 8a5df3 ebf1 8d45f4 c645ff00 50 8bd6 }
		$sequence_5 = { 8bc2 c1e802 c1e103 8b0483 d3e8 880432 42 }
		$sequence_6 = { 8d4ddc e8???????? 8d4d90 e8???????? 8d4d84 e8???????? }
		$sequence_7 = { c74610fe33b90f c7461465dc040b c74618e3804800 c7461cb5492c0d c7462045909c0f c74624dd90c504 c7462870e8f00e }
		$sequence_8 = { 0f1145c1 885ddf 0fbe4581 250f000080 7905 48 83c8f0 }
		$sequence_9 = { 40 83f806 7305 8a5df2 ebf1 8d45f3 c645f900 }

	condition:
		7 of them and filesize <524288
}
