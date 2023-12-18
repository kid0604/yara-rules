rule win_scarabey_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.scarabey."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.scarabey"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8bf0 85f6 7478 8b8dfcd6ffff 8b95f4d6ffff 8d85fcd6ffff 50 }
		$sequence_1 = { e8???????? c745fcffffffff 8b06 8b7e04 2bf8 85c0 7409 }
		$sequence_2 = { 51 52 ffd3 6a40 6800300000 }
		$sequence_3 = { ff15???????? 56 ff15???????? a1???????? 33f6 56 }
		$sequence_4 = { ba12000000 8d0dd0ad5700 e9???????? db2d???????? d9c9 d9f5 9b }
		$sequence_5 = { 7d04 8944241c 686666aa00 50 33db 6a02 895c2450 }
		$sequence_6 = { 8bc8 8b8524d7ffff 83c005 8d14c500000000 2bd0 a1???????? 03ca }
		$sequence_7 = { e8???????? 8b4d08 8b83d40c0000 8bf0 83f907 7771 ff248d690c4700 }
		$sequence_8 = { eb4c 8d4c2404 68???????? 51 e8???????? 83c408 84c0 }
		$sequence_9 = { c744240808000000 c744240cff000000 ff15???????? 8bce e8???????? 6a00 e8???????? }

	condition:
		7 of them and filesize <3580928
}
