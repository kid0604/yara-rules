rule win_lyposit_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.lyposit."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lyposit"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff510c 3bc3 0f8cf1000000 57 6a40 ffd6 8945dc }
		$sequence_1 = { ff74240c 50 e8???????? a3???????? 59 }
		$sequence_2 = { 33f6 8975d8 8975fc b9???????? e8???????? 50 e8???????? }
		$sequence_3 = { 6a01 e8???????? 83c40c 397d10 7413 ff7510 }
		$sequence_4 = { ff15???????? 8bf8 8975d8 6a04 803e55 7506 8d4601 }
		$sequence_5 = { 83c40c 83f801 0f8556010000 015f3c 295f58 807f6c00 }
		$sequence_6 = { 0f8479010000 8bd8 8b5768 03573c 8b4760 33f6 }
		$sequence_7 = { 29775c 0175fc 837df801 894750 8b475c 743e }
		$sequence_8 = { e8???????? 8945c4 8d4de0 51 ff75d0 56 }
		$sequence_9 = { 8bfe e8???????? 33c0 eb0f 6a08 6a40 ffd3 }

	condition:
		7 of them and filesize <466944
}