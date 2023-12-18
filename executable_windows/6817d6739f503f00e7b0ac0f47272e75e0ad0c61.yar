rule win_gemcutter_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.gemcutter."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gemcutter"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff75fc ff15???????? eb09 ff75fc ff15???????? 3975fc }
		$sequence_1 = { 8d8500fcffff 50 e8???????? 59 56 ff15???????? }
		$sequence_2 = { 56 ffd7 53 56 56 56 }
		$sequence_3 = { 59 53 50 ffd6 0fbe85f0f8ffff 50 }
		$sequence_4 = { 6a01 ff15???????? 6a01 68???????? e8???????? 6a01 }
		$sequence_5 = { 50 ff15???????? 83c420 8818 8d85f0fdffff 50 8d85f0f8ffff }
		$sequence_6 = { 8d85f0fdffff 50 ffd7 8d85f0f8ffff 6800040000 50 }
		$sequence_7 = { 8d45ac 56 50 e8???????? 83c40c 8d45f0 c745d801000000 }
		$sequence_8 = { ff15???????? 85c0 0f84df000000 8d85f0f8ffff 68???????? 50 e8???????? }
		$sequence_9 = { c3 55 8bec 81ec00040000 56 57 68???????? }

	condition:
		7 of them and filesize <40960
}
