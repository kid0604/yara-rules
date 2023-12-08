rule win_ratankba_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.ratankba."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ratankba"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7524 ff15???????? 89831c010000 39bd8cefffff 0f82b00e0000 8b8d78efffff }
		$sequence_1 = { 8b5508 833a00 0f95c0 8b4df4 }
		$sequence_2 = { e9???????? 8b4f0c 894de4 8b4d08 }
		$sequence_3 = { 897e04 8b4d08 8b5104 8b450c 895014 8b4908 5f }
		$sequence_4 = { 668911 e8???????? c645fc08 8d8e20010000 899e1c010000 33c0 897914 }
		$sequence_5 = { e8???????? 8bb59cd5ffff 53 8d8dbcd5ffff 51 83c8ff 8d7e08 }
		$sequence_6 = { 85c0 740b 50 e8???????? 83c404 891e 33c0 }
		$sequence_7 = { e8???????? 039de0feffff 8b85e4feffff 83c418 83bdf8feffff10 7306 }
		$sequence_8 = { 7407 50 ff15???????? 8b8508efffff }
		$sequence_9 = { 8945e4 8bc6 e8???????? 8b4804 8b55f4 8b44ca04 8b4de4 }

	condition:
		7 of them and filesize <303104
}
