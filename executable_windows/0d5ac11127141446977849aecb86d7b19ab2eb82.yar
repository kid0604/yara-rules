rule win_cryptbot_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.cryptbot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cryptbot"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 33c0 85ed 0f94c0 8be8 }
		$sequence_1 = { 33c0 eb0a b917d90000 e8???????? }
		$sequence_2 = { e9???????? b949dc0000 e9???????? b944dc0000 e9???????? b964dc0000 }
		$sequence_3 = { e8???????? 85c0 750c b961030200 e8???????? }
		$sequence_4 = { 0f9cc0 eb02 32c0 84c0 }
		$sequence_5 = { eb0c b99fed0000 e8???????? 8907 }
		$sequence_6 = { e8???????? 85c0 750e b9ca070200 e8???????? 8bc8 }
		$sequence_7 = { e8???????? 85c0 750f b955960100 e8???????? e9???????? }
		$sequence_8 = { 744e 0fb74802 83e103 3bcb }
		$sequence_9 = { 750b 8bce e8???????? 8b4c2428 }
		$sequence_10 = { 7508 85f6 7404 c6464101 5e c3 }
		$sequence_11 = { 7518 8b542414 83c718 8bcd }
		$sequence_12 = { 7409 33d2 e8???????? 8bf8 43 }
		$sequence_13 = { 2403 80e110 8ad1 3c02 7509 }
		$sequence_14 = { 751f 8bd5 8bce e8???????? }

	condition:
		7 of them and filesize <11116544
}