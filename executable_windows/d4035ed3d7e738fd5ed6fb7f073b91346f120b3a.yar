rule win_shipshape_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.shipshape."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shipshape"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 68???????? 68???????? 8d942440020000 68???????? 52 }
		$sequence_1 = { 83e103 50 f3a4 ffd3 e9???????? 56 e8???????? }
		$sequence_2 = { 68???????? 8d942440020000 68???????? 52 e8???????? 83c434 }
		$sequence_3 = { c1f905 8b0c8d60d54000 f644c10401 8d04c1 7403 8b00 }
		$sequence_4 = { 8d542438 8d842400070000 52 50 }
		$sequence_5 = { 8d84244c040000 68???????? 50 e8???????? 8d8c2454040000 51 }
		$sequence_6 = { 8d4c2414 50 51 6a00 6a00 6a00 }
		$sequence_7 = { 5b 81c440060000 c3 56 57 }
		$sequence_8 = { 50 51 ffd3 5f 5e 33c0 }
		$sequence_9 = { 83c418 3bc6 7e0f 5f 5e }

	condition:
		7 of them and filesize <338386
}
