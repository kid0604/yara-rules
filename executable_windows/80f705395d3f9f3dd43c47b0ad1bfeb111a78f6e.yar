rule win_maggie_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.maggie."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.maggie"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? e8???????? 84c0 74ec e8???????? }
		$sequence_1 = { ff15???????? 83f8ff 750f ff15???????? 2d33270000 f7d8 1bc0 }
		$sequence_2 = { 83f8ff 750f ff15???????? 2d33270000 f7d8 1bc0 }
		$sequence_3 = { 750f ff15???????? 2d33270000 f7d8 1bc0 }
		$sequence_4 = { ff15???????? 83f8ff 750f ff15???????? 2d33270000 f7d8 }
		$sequence_5 = { 83f8ff 750f ff15???????? 2d33270000 f7d8 }
		$sequence_6 = { b8ff000000 663b05???????? 7505 e8???????? e8???????? 84c0 }
		$sequence_7 = { 663b05???????? 7505 e8???????? e8???????? 84c0 }
		$sequence_8 = { 7511 ff15???????? 85c0 7407 33c0 }
		$sequence_9 = { 7511 ff15???????? 85c0 7407 33c0 e9???????? }

	condition:
		7 of them and filesize <611328
}
