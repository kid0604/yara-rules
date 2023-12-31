rule win_lightlesscan_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.lightlesscan."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lightlesscan"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 33db 48895c2460 488b4d70 4885c9 7405 e8???????? }
		$sequence_1 = { b890100000 e8???????? 482be0 48c7442458feffffff 48899c24c8100000 4889b424d0100000 4889bc24d8100000 }
		$sequence_2 = { 4863d8 e8???????? 488bd3 b940000000 ffd0 488d0deaa20300 c705????????01000000 }
		$sequence_3 = { 488d0d50c00100 e8???????? 4983c8ff ba80000000 488905???????? 488d0da05d0500 4885c0 }
		$sequence_4 = { 4881c440020000 5b f3c3 8815???????? 0100 a9150100c7 150100d615 }
		$sequence_5 = { 498bcc e8???????? 488d1564b70500 41b804000000 498bcc e8???????? 488d1567b70500 }
		$sequence_6 = { 4889442420 e8???????? eb0c 4c8d0d68440100 e8???????? 488d0d8cc10100 }
		$sequence_7 = { 488d0d23b40600 ffd0 48833d????????00 7415 488d0db04a0300 e8???????? 488b0d???????? }
		$sequence_8 = { 7506 ff15???????? 4489bc24f8000000 488b07 418bf7 0fb74814 }
		$sequence_9 = { 488d4d30 33d2 41b801100000 e8???????? 33d2 41b8faff0000 488bce }

	condition:
		7 of them and filesize <1399808
}
