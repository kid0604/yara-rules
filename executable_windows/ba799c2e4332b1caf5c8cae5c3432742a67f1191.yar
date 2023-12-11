rule win_bubblewrap_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.bubblewrap."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bubblewrap"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 750b c1ed0a 892d???????? eb0c c1ed0a }
		$sequence_1 = { b988130000 f7f1 81c2e8030000 52 ffd5 43 }
		$sequence_2 = { 8b9384010000 83c404 8d441019 50 e8???????? 8b4c2418 83c408 }
		$sequence_3 = { 8d4c2420 50 51 ff15???????? 8b542434 8b442432 }
		$sequence_4 = { b099 884c2441 b910000000 8d74240c 8d7c240c c644240c2c c644240e15 }
		$sequence_5 = { 56 57 a1???????? 83c005 8945fc 6a00 }
		$sequence_6 = { 8d542464 68???????? 52 ffd7 85c0 }
		$sequence_7 = { c6442413b9 c644241546 c6442416d2 c644241755 c6442418c4 c644241979 c644241b8d }
		$sequence_8 = { ffd6 68???????? ffd6 8b5c241c }
		$sequence_9 = { c1e902 f3a5 8bca 83e103 f3a4 e8???????? 8b0d???????? }

	condition:
		7 of them and filesize <57136
}
