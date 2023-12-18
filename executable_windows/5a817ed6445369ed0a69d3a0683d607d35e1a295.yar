rule win_polyglot_ransom_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.polyglot_ransom."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.polyglot_ransom"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff74244c e8???????? 8944241c 894c2448 6a07 895c2450 }
		$sequence_1 = { 6a30 e8???????? 59 59 8d4d80 51 6801010000 }
		$sequence_2 = { ff5004 83c328 ff4d10 75ad ff75f0 ff15???????? }
		$sequence_3 = { be???????? 66f7c30040 6a04 5a 747a 6681fb0b40 756c }
		$sequence_4 = { 50 68???????? e8???????? 8b85f0fdffff 59 59 8b08 }
		$sequence_5 = { 627265 206f20 656c 696d696e617220 61 7263 6869766f73 }
		$sequence_6 = { eb4f 8bf3 8bf9 a5 a5 a5 a5 }
		$sequence_7 = { 59 59 751c 8b45fc 8b4020 85c0 }
		$sequence_8 = { 5e c20400 68???????? 6a20 33c0 }
		$sequence_9 = { 40 5e eb02 32c0 8b4d74 33cd }

	condition:
		7 of them and filesize <1392640
}
