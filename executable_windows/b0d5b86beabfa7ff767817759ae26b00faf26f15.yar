rule win_bhunt_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.bhunt."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bhunt"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { feca f8 d0c2 f5 f8 32da 80ffd4 }
		$sequence_1 = { 85c0 751a 8b442410 50 8bd5 8bc3 e8???????? }
		$sequence_2 = { 8902 660fbcc0 8b07 8dbf04000000 663bcf 66f7c4ab75 33c3 }
		$sequence_3 = { bbff000000 8bc3 8d7c2414 66c784241e1200000800 e8???????? 59 8d8600120000 }
		$sequence_4 = { 0fb7c2 8b55f0 03450c 2bd1 0fb74dfc }
		$sequence_5 = { ff7304 c645d405 56 e8???????? ff7304 ff36 e8???????? }
		$sequence_6 = { 83a530ffffff00 c7852cffffff01000000 ffb530ffffff ffb52cffffff 52 ffb544ffffff e8???????? }
		$sequence_7 = { 5f 9c 04f8 26ed c59818579fa0 5f e7e6 }
		$sequence_8 = { 52 3a21 a7 a2???????? 50 9d 03890023b0b3 }
		$sequence_9 = { ac 2a7279 bfae9603f7 6c a3???????? 9f 97 }

	condition:
		7 of them and filesize <19161088
}
