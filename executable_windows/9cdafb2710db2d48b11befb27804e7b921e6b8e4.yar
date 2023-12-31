rule win_farseer_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.farseer."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.farseer"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8d4c2434 e8???????? eb10 6a06 68???????? 8d4c2438 }
		$sequence_1 = { 50 8d4c2440 51 8d542478 }
		$sequence_2 = { e8???????? 8d742414 e8???????? 53 50 83c8ff 8d742438 }
		$sequence_3 = { 8d442434 50 e8???????? c68424c402000002 8b8424cc000000 bb10000000 399c24e0000000 }
		$sequence_4 = { 0f8c6cffffff 33ed 8d9424ac010000 68???????? 52 e8???????? 83c408 }
		$sequence_5 = { 33db 6aff 899c2498000000 53 8d8424a4000000 be0f000000 50 }
		$sequence_6 = { 7510 8bc1 eb0c 0fb6c9 0fbe8940454200 03c1 40 }
		$sequence_7 = { 83c404 83bc24e402000010 7210 8b9424d0020000 52 e8???????? 83c404 }
		$sequence_8 = { 85410c 7405 e8???????? 8d742440 e8???????? 85c0 }
		$sequence_9 = { e9???????? 8bc3 c1f805 8d048520634200 83e31f 8985e4efffff 8b00 }

	condition:
		7 of them and filesize <347328
}
