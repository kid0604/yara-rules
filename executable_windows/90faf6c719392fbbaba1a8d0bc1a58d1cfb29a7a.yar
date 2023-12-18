rule win_downeks_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.downeks."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.downeks"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e9???????? 8b8ddcfeffff 51 ff15???????? 8b8de0feffff 53 }
		$sequence_1 = { c3 8b4108 c3 b8ccd00904 c3 8bff 55 }
		$sequence_2 = { 8d4da0 e8???????? 8b4704 85c0 7409 83f8ff 7304 }
		$sequence_3 = { e8???????? 8bd8 83c40c 85db 0f85cf000000 8b55c0 85d2 }
		$sequence_4 = { 2bce 51 8bce 2b4d80 8d75a8 8d558c e8???????? }
		$sequence_5 = { e9???????? 8d75b4 e9???????? 8d75d0 e9???????? 8bb560ffffff e9???????? }
		$sequence_6 = { c785e8faffff07000000 89b5e4faffff 668995d4faffff e8???????? 8975fc 80fb5c 740a }
		$sequence_7 = { c1ea08 0fb6d2 8b3c95a0c20804 0fb6d0 8b1495a0c60804 c1e808 0fb6c0 }
		$sequence_8 = { ff15???????? 8bf0 83c42c 85f6 0f8547feffff 8b45f0 50 }
		$sequence_9 = { 7488 8b4d0c 833900 7502 8901 8b4d10 8b13 }

	condition:
		7 of them and filesize <1318912
}
