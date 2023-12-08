rule win_wscspl_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.wscspl."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wscspl"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 2bc2 51 8bd8 e8???????? 83c404 8b74240c }
		$sequence_1 = { 52 6a00 ff15???????? 0fb744241a }
		$sequence_2 = { 888c0480030000 40 84c9 75ee 8d842480030000 48 }
		$sequence_3 = { 33c9 e9???????? 57 6a00 }
		$sequence_4 = { 8d442430 50 6a02 ff15???????? 33c0 8d4c240c 51 }
		$sequence_5 = { 03c9 3bc1 7702 8bc1 }
		$sequence_6 = { 81fe7c230000 7627 b885b7dce6 f7e6 c1ea0d 8bca 69d27c230000 }
		$sequence_7 = { ff15???????? 6689442402 a1???????? 85c0 7419 }
		$sequence_8 = { c1ea0d 8bca 69d27c230000 8bc6 2bc2 890d???????? }
		$sequence_9 = { e8???????? 8d4c2450 885c2c50 8b2d???????? 51 ffd5 }

	condition:
		7 of them and filesize <901120
}
