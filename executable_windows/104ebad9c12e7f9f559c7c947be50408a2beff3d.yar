rule win_blackpos_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.blackpos."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackpos"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 57 50 e8???????? 83c40c 56 8d85e0fdffff }
		$sequence_1 = { 46 83bddcfbffff1e 0f8c44ffffff 807d2000 754a }
		$sequence_2 = { f7fb 85d2 740d 8bc6 c1e002 8bb070f84100 }
		$sequence_3 = { 7444 8b4508 53 57 8b7d0c }
		$sequence_4 = { ffd6 85c0 759c 8b85f8fbffff 8b4dfc 5f 5e }
		$sequence_5 = { c1e006 03048d60c45800 eb05 b8???????? f6402480 7414 }
		$sequence_6 = { 83c40c 6bc930 8975e0 8db1a0f34100 8975e4 eb2b 8a4601 }
		$sequence_7 = { 7429 ffb5f4fbffff 8d85d8fbffff 50 57 e8???????? }
		$sequence_8 = { 85f6 7426 56 8d85fcfbffff }
		$sequence_9 = { 7517 e8???????? eb10 8d45c4 }

	condition:
		7 of them and filesize <3293184
}
