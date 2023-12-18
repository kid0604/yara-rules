rule win_shujin_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.shujin."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shujin"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? ff7660 8b1d???????? 6a01 bf80000000 57 }
		$sequence_1 = { ff15???????? 85c0 0f8431010000 53 897df4 }
		$sequence_2 = { 6aff 50 ff15???????? 57 8b7d10 83ff01 }
		$sequence_3 = { 8bf9 ba???????? 0fb67201 8a0a 8b1f d3e3 0fb60c06 }
		$sequence_4 = { 83615400 53 56 57 8d7108 c7450805000000 8b46f8 }
		$sequence_5 = { ff45f8 817df870170000 72c9 e9???????? 807daa01 8b45e8 8d1c06 }
		$sequence_6 = { 8b5508 0facc21a c1f81a 8bd8 8955e4 }
		$sequence_7 = { c1ef10 8d8d9cf9ffff 2bf9 03f8 a0???????? a801 7421 }
		$sequence_8 = { 895008 8b680c 8bd5 896c2410 }
		$sequence_9 = { 8d1c06 83c40c 8975f8 3bf3 731e }

	condition:
		7 of them and filesize <172032
}
