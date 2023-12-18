rule win_tonedeaf_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.tonedeaf."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tonedeaf"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 56 ff15???????? 56 ff15???????? 56 e8???????? }
		$sequence_1 = { 2bf1 8bc3 46 d1e8 }
		$sequence_2 = { 8bc3 46 d1e8 33d2 }
		$sequence_3 = { 8b45ec 85c0 740b 6a08 50 }
		$sequence_4 = { 884c32ff 84c9 75f3 8bf3 8a03 43 84c0 }
		$sequence_5 = { 8b5004 8d4af8 898c153cffffff 8d45a8 c745fc01000000 50 }
		$sequence_6 = { 56 6a00 ff15???????? 56 ff15???????? 56 ff15???????? }
		$sequence_7 = { 83f801 732f 8b0f 8bc1 }
		$sequence_8 = { 0f57c0 c745dc00000000 33c0 660fd645d4 33db 8945d8 }
		$sequence_9 = { 75f3 8bf3 8a03 43 84c0 75f9 }

	condition:
		7 of them and filesize <851968
}
