rule win_crutch_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.crutch."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.crutch"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7536 8b8740030000 f7404000c00000 51 740f 8b4e6c 51 }
		$sequence_1 = { 8b442430 85c0 742b 8b942488000000 8b8c2484000000 52 8b54243c }
		$sequence_2 = { 8b01 50 ff30 51 ff32 8bcb e8???????? }
		$sequence_3 = { 50 8d4ddc e8???????? eb3a 8dbd1cffffff 8d3cd7 8d8514ffffff }
		$sequence_4 = { 8b6c2408 7426 8b03 50 ff15???????? 8b8efc040000 51 }
		$sequence_5 = { 0f84f9000000 b9???????? 8bc6 8d642400 8a10 3a11 751a }
		$sequence_6 = { 81c2cc000000 89542408 8b54240c 89542404 e9???????? 81f9244e0000 }
		$sequence_7 = { 7506 8b7c2428 eb4a 41 51 ff15???????? 8bf8 }
		$sequence_8 = { b823000000 5e c3 8d471f c1e004 8bcf c1e104 }
		$sequence_9 = { 8bf1 8a02 8806 8d4e18 8b4208 894608 8b420c }

	condition:
		7 of them and filesize <1067008
}
