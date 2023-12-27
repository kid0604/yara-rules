rule win_jaff_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.jaff."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.jaff"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c746080a000000 c6460c01 ffd7 8b1d???????? 50 ffd3 6a14 }
		$sequence_1 = { 8bf8 e8???????? 8b4704 48 7818 }
		$sequence_2 = { 8b4514 8b4d10 6a00 8d55fc 52 50 51 }
		$sequence_3 = { 72ed 8b45dc 50 6a00 ffd7 50 }
		$sequence_4 = { ffd3 8945f0 8b450c 8d5de0 8d4df0 e8???????? 8b45e0 }
		$sequence_5 = { 3b4510 0f82a5feffff 8b4d14 51 6a00 }
		$sequence_6 = { 8d5598 52 8d45cc 50 e8???????? 8d7da8 }
		$sequence_7 = { 33c2 2bc2 50 8d95f8fbffff 68???????? }
		$sequence_8 = { 8d4584 e8???????? 8d7da4 8d75e4 e8???????? 8b55a4 8b3d???????? }
		$sequence_9 = { c745f00a000000 c645f401 ffd3 50 ff15???????? 8945e8 }

	condition:
		7 of them and filesize <106496
}