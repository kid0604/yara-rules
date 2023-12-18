rule win_rambo_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.rambo."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rambo"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff7508 e8???????? 59 50 ff7508 ff15???????? 56 }
		$sequence_1 = { e8???????? ff750c 8d85ecfdffff 50 e8???????? }
		$sequence_2 = { ff15???????? 83c41c 6a01 58 5e c9 }
		$sequence_3 = { 85f6 7437 56 6a01 }
		$sequence_4 = { ff7508 8d85f8feffff 50 e8???????? 8065fe00 8d45fc 50 }
		$sequence_5 = { 83c428 6a32 ff15???????? 8d85f8faffff 50 68???????? }
		$sequence_6 = { 56 57 8d85f8faffff 6a01 50 ff15???????? 80a43df8faffff00 }
		$sequence_7 = { 50 8d85f8feffff 50 c645fc72 }
		$sequence_8 = { 756b 57 b940000000 8d7c240d 8844240c f3ab }
		$sequence_9 = { f3aa 8bcb 8d7c2474 8bc1 }
		$sequence_10 = { e8???????? 8d4c2410 c684240004000007 e8???????? 68b6000000 8d542414 }
		$sequence_11 = { 8d8c2488000000 e8???????? 57 57 8d4c2424 }
		$sequence_12 = { e8???????? 8d4c2428 c684240004000005 e8???????? 8d4c2414 c684240004000004 }
		$sequence_13 = { 8b35???????? a3???????? ffd6 3db7000000 7418 }
		$sequence_14 = { 89442418 8b4309 84c9 7403 50 }
		$sequence_15 = { f3a5 8bcb 8d9424f8020000 83e103 f3a4 bf???????? 83c9ff }

	condition:
		7 of them and filesize <57344
}
