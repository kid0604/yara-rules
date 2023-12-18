rule win_scout_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.scout."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.scout"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 488d537c 41b888140000 488d4df0 e8???????? 41b904000000 }
		$sequence_1 = { 498bf9 8b0a e8???????? 90 488d1d86780100 488d356f630100 }
		$sequence_2 = { 736b 488bc3 488bf3 48c1fe06 4c8d2d4ef80000 }
		$sequence_3 = { 4d8bf8 488bc6 48894df7 488945ef 488d0d36fbfeff 83e03f 458be9 }
		$sequence_4 = { 488d1520d50000 b805000000 894520 894528 }
		$sequence_5 = { 7566 b804000000 660f1f840000000000 488d8980000000 }
		$sequence_6 = { e8???????? 33c0 488b8d90140000 4833cc e8???????? }
		$sequence_7 = { c745dca8837182 0f1045d0 c744242801000000 8905???????? }
		$sequence_8 = { 4c89742438 4c897c2430 ff15???????? 33d2 }
		$sequence_9 = { 75dd 488d05e31b0100 483bd8 74d1 488bcb }

	condition:
		7 of them and filesize <315392
}
