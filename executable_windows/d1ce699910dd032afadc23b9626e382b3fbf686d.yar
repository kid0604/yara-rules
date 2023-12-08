rule win_rombertik_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.rombertik."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rombertik"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 46 0fb68c3500ffffff 03f9 81e7ff000080 }
		$sequence_1 = { 53 56 57 b940010000 8d85b4feffff }
		$sequence_2 = { 2bf8 83ef05 c60406e9 897c0601 }
		$sequence_3 = { 85c0 0f8406010000 53 56 8b35???????? 57 }
		$sequence_4 = { 85c0 743b 807dfee9 7435 56 }
		$sequence_5 = { 8b35???????? 6a00 6a01 6a00 6a00 8d45fc }
		$sequence_6 = { ffd6 85c0 740f 8d95acfdffff 52 }
		$sequence_7 = { 8d8df8feffff 51 c745fc04010000 ff15???????? }
		$sequence_8 = { 8b5508 8b7510 03d7 8ac3 2bf1 3c78 }
		$sequence_9 = { 50 52 8d85f4feffff 57 50 e8???????? }

	condition:
		7 of them and filesize <73728
}
