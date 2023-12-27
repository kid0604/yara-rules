rule win_datper_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.datper."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.datper"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 33c9 ba0c000000 e8???????? c78564d7ffff0c000000 33c0 898568d7ffff }
		$sequence_1 = { 5a 59 59 648910 68???????? 8d85e8f3ffff }
		$sequence_2 = { 0fb607 8845f7 0fb6c1 8b55fc 0fb60402 8807 }
		$sequence_3 = { 50 ff15???????? 85c0 741f 8b8424a80d0000 894348 }
		$sequence_4 = { 895de4 895de8 895df4 894df0 8955f8 8945fc 8d45fc }
		$sequence_5 = { 53 e8???????? a3???????? 8d95a8fbffff b8???????? e8???????? 8b85a8fbffff }
		$sequence_6 = { c78568d7ffff0c000000 33c0 89856cd7ffff c78570d7ffffffffffff 6a00 6a01 8d8568d7ffff }
		$sequence_7 = { 8b45fc e8???????? 50 e8???????? 8d8564d7ffff 33c9 ba0c000000 }
		$sequence_8 = { 8d85f0fbffff 50 53 e8???????? 8945f0 a1???????? 50 }
		$sequence_9 = { 53 e8???????? 6800800000 6a00 56 }

	condition:
		7 of them and filesize <253952
}