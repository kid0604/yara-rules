rule win_thanatos_ransom_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.thanatos_ransom."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.thanatos_ransom"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 68???????? 8bd0 c645fc0a 8d4dc0 e8???????? 83c404 }
		$sequence_1 = { 50 c745f407000000 c745f000000000 e8???????? 837df408 8d4de0 8b4610 }
		$sequence_2 = { 83c404 68???????? 8bd0 c645fc13 8d4dc0 e8???????? 83c404 }
		$sequence_3 = { 6a00 53 ff15???????? 85c0 0f8407020000 0f1f840000000000 8d8570ffffff }
		$sequence_4 = { 51 66894de0 8d4de0 50 }
		$sequence_5 = { 8b8584feffff 83f810 7245 8b8d70feffff }
		$sequence_6 = { c785e4feffff0f000000 c785e0feffff00000000 c685d0feffff00 83f810 7245 8b8d88feffff 40 }
		$sequence_7 = { 6a00 6a00 53 e8???????? 8b0cbde0774300 }
		$sequence_8 = { 57 8b0485e0774300 80640828fe ff15???????? }
		$sequence_9 = { 83f81d 7cf1 eb07 8b0cc544be4200 894de4 }

	condition:
		7 of them and filesize <516096
}
