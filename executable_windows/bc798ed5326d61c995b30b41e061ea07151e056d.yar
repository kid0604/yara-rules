rule win_kuluoz_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.kuluoz."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kuluoz"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6a00 6a00 8b45cc 50 ff55ec 8945c8 837dc800 }
		$sequence_1 = { 52 8b45fc 8b4840 51 e8???????? 83c40c 8b55fc }
		$sequence_2 = { 83c001 8b4d0c 898146120000 837dfc04 7552 }
		$sequence_3 = { 8b4508 50 8d4dd8 51 e8???????? 8b10 }
		$sequence_4 = { 338df4feffff 8985f0feffff 898df4feffff 68ff000000 8d95f8feffff 52 e8???????? }
		$sequence_5 = { 7502 eb05 e9???????? 837dfc06 0f84a2000000 837dfc04 7552 }
		$sequence_6 = { 83fa0a 7409 0fbe4508 83f80d 7504 b001 }
		$sequence_7 = { 8b45fc 0fb60c02 51 e8???????? 0fbed0 3bf2 7404 }
		$sequence_8 = { 8bec 81ec780a0000 a1???????? 33c5 8945fc }
		$sequence_9 = { f7f1 0fbe9204605009 8b45f8 0345fc 0fbe08 }

	condition:
		7 of them and filesize <65536
}