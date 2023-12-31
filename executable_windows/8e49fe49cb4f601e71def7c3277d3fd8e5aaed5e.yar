rule win_spora_ransom_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.spora_ransom."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spora_ransom"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6a3a 8d4641 668945f0 58 ff7510 668945f2 ff750c }
		$sequence_1 = { f6c301 742c 6a3a 8d4641 668945f0 58 ff7510 }
		$sequence_2 = { 897df4 85ff 747a 834d08ff }
		$sequence_3 = { 834d08ff 8d45f8 50 57 8d4508 50 }
		$sequence_4 = { 8d4641 668945f0 58 ff7510 668945f2 ff750c 33c0 }
		$sequence_5 = { 33c0 668945f4 8d45f0 50 ff15???????? 50 8d45f0 }
		$sequence_6 = { 0fb600 48 50 ff36 ff15???????? 85c0 }
		$sequence_7 = { c745c800040000 33f6 8d45c4 50 ff15???????? 85c0 750e }
		$sequence_8 = { 50 ff15???????? 85c0 7466 56 57 bf00020000 }
		$sequence_9 = { 0bf0 57 ff15???????? 5f 8bc6 }

	condition:
		7 of them and filesize <73728
}
