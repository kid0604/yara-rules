rule win_himera_loader_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.himera_loader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.himera_loader"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 660fd60f 8d7f08 8b048da4bd4000 ffe0 f7c703000000 7413 8a06 }
		$sequence_1 = { 894de0 c745e4343f4200 e9???????? c745e003000000 }
		$sequence_2 = { c645e84d c645e94b c645ea00 c645eb4b c645ec56 c645ed4b }
		$sequence_3 = { e8???????? 83c404 85c0 7405 e8???????? 33c0 88855682ffff }
		$sequence_4 = { 8b45fc 83c001 8945fc 837dfc0c 730b 8b4df8 }
		$sequence_5 = { 0f8483000000 eb7d 8b1c9db8fe4100 6800080000 }
		$sequence_6 = { 6bf838 894df4 8b048d00a14200 c745f00a000000 8b540718 8955e0 }
		$sequence_7 = { 8d8d4782ffff e8???????? 89852482ffff 33c0 88855282ffff 8d8d5282ffff e8???????? }
		$sequence_8 = { 8b048d00a14200 f644102840 7405 803b1a 741d e8???????? c7001c000000 }
		$sequence_9 = { 83e03f c1f906 6bf038 03348d00a14200 837e18ff 740c }

	condition:
		7 of them and filesize <385024
}
