rule win_redpepper_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.redpepper."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.redpepper"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 57 8bf9 8b870c1e0000 85c0 }
		$sequence_1 = { 8b500c 41 83f904 8b12 8a540aff }
		$sequence_2 = { 8b4d10 881e 50 8901 e8???????? 59 }
		$sequence_3 = { 8b4520 3bc7 7439 68a1000000 68???????? 50 e8???????? }
		$sequence_4 = { 53 55 56 33f6 57 8b7c2428 }
		$sequence_5 = { 752d 689f000000 68???????? 6a26 }
		$sequence_6 = { c3 8b7c2418 85ff 7432 e8???????? }
		$sequence_7 = { 8845f3 8845f4 8845f7 8845f8 }
		$sequence_8 = { 8b742414 6a0f f7d1 49 56 8be9 e8???????? }
		$sequence_9 = { e8???????? 8b44241c 8b6c2428 8b4c2418 }

	condition:
		7 of them and filesize <2482176
}
