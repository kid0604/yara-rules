rule win_unidentified_003_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.unidentified_003."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_003"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8945ec a1???????? 0fb7506f 0fb7406d c1e210 0bd0 }
		$sequence_1 = { c68564ffffff01 33c0 8a88c2100900 888c0566ffffff 40 }
		$sequence_2 = { e8???????? 83c40c 8b07 5d c3 55 8bec }
		$sequence_3 = { a1???????? ff75f0 ff7028 ff15???????? eb0a }
		$sequence_4 = { 395da0 740f ff75a4 ff15???????? 895da0 }
		$sequence_5 = { 3bfe 7502 8bfb 39742410 }
		$sequence_6 = { 59 85c0 7417 47 81c614010000 3b3d???????? 72c8 }
		$sequence_7 = { 8bec 81ec20080000 53 56 57 8d85e0fdffff 8945ec }
		$sequence_8 = { 7575 385d6e 743b 39bd5cffffff 750a c705????????07000000 399d5cffffff }
		$sequence_9 = { ff15???????? 85c0 0f88b4010000 8b45e4 3bc3 0f84a9010000 8b08 }

	condition:
		7 of them and filesize <57344
}
