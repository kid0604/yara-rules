rule win_graphdrop_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.graphdrop."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.graphdrop"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 4154 90 415c 90 }
		$sequence_1 = { 4155 49c7c501000000 4150 4152 415a }
		$sequence_2 = { 52 0f77 90 5a }
		$sequence_3 = { 0f77 0f77 5b 0f77 }
		$sequence_4 = { 49c7c501000000 4150 4152 415a 4158 }
		$sequence_5 = { 52 50 58 5a 49ffc9 }
		$sequence_6 = { 49c7c501000000 4150 4152 415a 4158 49ffcd }
		$sequence_7 = { 4150 4152 415a 4158 }
		$sequence_8 = { 4155 49c7c501000000 4150 4152 415a 4158 49ffcd }
		$sequence_9 = { 4152 415a 4158 49ffcd }

	condition:
		7 of them and filesize <4186112
}
