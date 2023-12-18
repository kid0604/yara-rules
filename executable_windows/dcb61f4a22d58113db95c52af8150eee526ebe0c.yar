rule win_darkpink_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.darkpink."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkpink"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b048d442a4000 ffe0 f7c703000000 7413 }
		$sequence_1 = { 57 50 683f000f00 6a00 68???????? 6801000080 }
		$sequence_2 = { c3 c705????????08924100 b001 c3 68???????? e8???????? c70424???????? }
		$sequence_3 = { 8d41fc 50 56 57 e8???????? 57 }
		$sequence_4 = { 8b85b0f8ffff 0fb70485c43c4100 8d0485c0334100 50 8d8590faffff 03c7 50 }
		$sequence_5 = { 33f6 8b86f09d4100 85c0 740e }
		$sequence_6 = { 68???????? ff75f4 ffd6 85c0 0f85ca000000 50 8d45f8 }
		$sequence_7 = { 8b0495f09d4100 f644082801 7421 57 }
		$sequence_8 = { e8???????? 6a44 8d45ac 6a00 50 }
		$sequence_9 = { 6a26 58 0fb60c85c63c4100 0fb63485c73c4100 8bf9 8985b0f8ffff c1e702 }

	condition:
		7 of them and filesize <237568
}
