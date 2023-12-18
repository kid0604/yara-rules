rule win_buzus_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.buzus."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.buzus"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 5d 7413 68???????? 50 ffd6 3bc3 a3???????? }
		$sequence_1 = { 4e 46 897508 ebbd 803e2a 750b 83f801 }
		$sequence_2 = { ff75c0 ff75bc 50 e8???????? 83c40c 83f801 0f85e4000000 }
		$sequence_3 = { e8???????? 8d8554fdffff 50 8d85ccfdffff 50 68???????? }
		$sequence_4 = { 68???????? 6a01 56 68???????? 33ff 8975f0 8975f4 }
		$sequence_5 = { 50 ff15???????? be???????? 8d84242c280000 }
		$sequence_6 = { 898524ffffff 8b45bc 89850cffffff 8b45d8 898514ffffff 6bc03c 6a31 }
		$sequence_7 = { 385802 750e 0fbe5001 c68415b0feffff01 eb28 80fa2d 7539 }
		$sequence_8 = { 6a03 58 8945b8 6a3c 59 3bc1 7603 }
		$sequence_9 = { 68???????? 50 ff7508 e8???????? 83c41c 8b45d4 68b80b0000 }

	condition:
		7 of them and filesize <679936
}
