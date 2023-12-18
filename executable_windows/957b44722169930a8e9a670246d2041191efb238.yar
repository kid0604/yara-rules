rule win_tabmsgsql_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.tabmsgsql."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tabmsgsql"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 33c0 f2ae f7d1 2bf9 8bd1 8bf7 8bbc24a4010000 }
		$sequence_1 = { 8a443901 c0fb02 8a80c8244100 c0e004 02c3 880416 }
		$sequence_2 = { 8882c8254100 48 42 83f841 }
		$sequence_3 = { 8bf8 75ce 8b6c2414 8b542418 b8ad8bdb68 }
		$sequence_4 = { 6804010000 8b842478030000 52 c744242844000000 c744245401010000 8b08 8b400c }
		$sequence_5 = { f2ae f7d1 49 8d85c8f7ffff }
		$sequence_6 = { 0f8eb2000000 8b7c2414 0fbe05???????? 33db 8a1c39 3bd8 }
		$sequence_7 = { ff15???????? b940000000 33c0 bf???????? 68???????? f3ab 68???????? }
		$sequence_8 = { a1???????? 50 ff15???????? b940000000 33c0 bf???????? }
		$sequence_9 = { 33c0 8a443901 c0fb02 8a80c8244100 c0e004 02c3 880416 }

	condition:
		7 of them and filesize <163840
}
