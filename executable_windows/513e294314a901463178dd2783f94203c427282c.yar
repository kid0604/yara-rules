rule win_unidentified_105_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.unidentified_105."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_105"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 85c0 0f95c0 84c0 742c }
		$sequence_1 = { 8bf8 8d4f02 b856555555 f7e9 8bc2 c1e81f 03c2 }
		$sequence_2 = { 6a00 8d8dd0feffff 51 8d95fcfeffff }
		$sequence_3 = { 8d8d94feffff 51 6800000010 50 52 ff15???????? 85c0 }
		$sequence_4 = { e8???????? 83c404 50 e8???????? a1???????? 6800020000 }
		$sequence_5 = { 83f8ff 7459 8d9424a0010000 52 }
		$sequence_6 = { 68???????? 56 e8???????? 8bc6 83c454 }
		$sequence_7 = { 8bf8 8d4f02 b856555555 f7e9 8bc2 }
		$sequence_8 = { 8b3d???????? 8d45e4 50 33f6 }
		$sequence_9 = { 6800100000 8d85f8efffff 50 51 }

	condition:
		7 of them and filesize <253952
}