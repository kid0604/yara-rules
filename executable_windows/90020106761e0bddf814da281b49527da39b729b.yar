rule win_billgates_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.billgates."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.billgates"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 3c11 7408 3c22 7404 3c30 }
		$sequence_1 = { 8d8809f9ffff b8c94216b2 f7e9 03d1 }
		$sequence_2 = { 3c58 7507 b802000000 eb02 }
		$sequence_3 = { 740c 3c11 7408 3c22 7404 3c30 }
		$sequence_4 = { 3c10 740c 3c11 7408 }
		$sequence_5 = { 83f8ff 750c ff15???????? 8bd8 f7db }
		$sequence_6 = { 3c11 7408 3c22 7404 }
		$sequence_7 = { ff15???????? 83f8ff 7508 ff15???????? f7d8 85c0 }
		$sequence_8 = { 3c10 740c 3c11 7408 3c22 }
		$sequence_9 = { 3c10 740c 3c11 7408 3c22 7404 }

	condition:
		7 of them and filesize <801792
}
