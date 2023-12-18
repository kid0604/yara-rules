rule win_get2_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.get2."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.get2"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b4004 f644080c06 74d5 8d4d84 e8???????? 8d4584 c645fc03 }
		$sequence_1 = { 0f859a000000 f6c104 7430 8d4c2404 e8???????? }
		$sequence_2 = { e8???????? ff7510 8d4dc0 ff750c e8???????? 83c420 83781410 }
		$sequence_3 = { 57 53 8d4dd8 e8???????? 8bc6 e8???????? c3 }
		$sequence_4 = { 33c0 895dd4 668945d8 51 51 52 }
		$sequence_5 = { 8d44240c 68???????? 50 eb69 f6c102 8d4c2404 742b }
		$sequence_6 = { 8b4910 23c8 0f849e000000 807d0c00 }
		$sequence_7 = { 897e08 33db c745ec07000000 43 897de8 }
		$sequence_8 = { 0f95c3 8bc3 488b5c2450 488b4c2448 }
		$sequence_9 = { 4533f6 4863df 488d0dbc730200 488bc3 83e33f }
		$sequence_10 = { 4885ff 75eb 33c0 48894110 }
		$sequence_11 = { 488bc8 0fb7045e 663901 740f 48ffc3 493bde }
		$sequence_12 = { 663931 7451 488d1590280100 e8???????? 85c0 7441 }
		$sequence_13 = { 7203 488b00 668938 488d8b40010000 }
		$sequence_14 = { 85c0 750d ff15???????? 41898660010000 4032ff }
		$sequence_15 = { 488b4708 4a8b4cf008 488b4618 4c3b24c8 0f85d0fbffff 488b4648 }

	condition:
		7 of them and filesize <720896
}
