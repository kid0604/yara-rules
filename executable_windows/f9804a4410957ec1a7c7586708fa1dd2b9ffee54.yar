rule win_atmosphere_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.atmosphere."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.atmosphere"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83ec14 56 8b7104 85f6 }
		$sequence_1 = { 88460e 33c0 894612 894616 89461a 884e1e }
		$sequence_2 = { e8???????? 8b4604 85c0 7504 33f6 eb08 }
		$sequence_3 = { 8bcf ff5338 5f 5e }
		$sequence_4 = { c645fc02 8bcc 8965e8 50 51 e8???????? }
		$sequence_5 = { 8bce 8975e8 8806 ff15???????? }
		$sequence_6 = { 8bc4 89642410 50 e8???????? }
		$sequence_7 = { 8b7c240c 8bf1 57 ff15???????? 8b470c }
		$sequence_8 = { 51 83ec10 8bc4 89642410 50 e8???????? }
		$sequence_9 = { 8bcc 8965e8 50 51 }

	condition:
		7 of them and filesize <360448
}
