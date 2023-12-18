rule win_chinoxy_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.chinoxy."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chinoxy"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8d4704 50 ff15???????? 8d8e90200000 c744241800000000 e8???????? 85c0 }
		$sequence_1 = { 8d842424010000 50 e8???????? 8b9318040000 8d8c2428010000 51 52 }
		$sequence_2 = { 2bcd c1e013 c1ef0d 0bc7 03ee 33c1 8bf8 }
		$sequence_3 = { 897e18 8b4c2410 895e10 895e14 8bc6 5f 5e }
		$sequence_4 = { e8???????? 85c0 741f 668b4c242c 6a08 66894802 50 }
		$sequence_5 = { 8b8ef0000000 8d86e8000000 3bc8 c744241c00000000 7405 394004 7538 }
		$sequence_6 = { 8d4c2410 6689542414 66895c2424 6689542430 66895c2438 66895c245c }
		$sequence_7 = { 8d8ec8020000 e8???????? 8d86d4020000 8b4c240c 894004 894008 c700???????? }
		$sequence_8 = { 894b10 03f2 8bd1 8bf8 c1e902 f3a5 8bca }
		$sequence_9 = { 17 08cb 8291975b9c2acc 8f81509c02d5 96 9e 664e }

	condition:
		7 of them and filesize <1138688
}
