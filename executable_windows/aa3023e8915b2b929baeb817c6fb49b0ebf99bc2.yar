rule win_slub_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.slub."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.slub"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8d4704 895f34 89470c 8d4f08 8d4714 8b5d08 89471c }
		$sequence_1 = { 8b06 05400c0000 50 56 53 e8???????? 83c414 }
		$sequence_2 = { 0f854b030000 8b4c241c 8bc5 0bc1 0f84b7000000 0f1f840000000000 8b4618 }
		$sequence_3 = { 83c40c 85c0 0f85af000000 8883b4090000 e9???????? 6a06 56 }
		$sequence_4 = { 8b8ef8010000 ff7120 ff7128 68???????? 57 e8???????? 83c434 }
		$sequence_5 = { 85ed 7414 81fd21030900 740c 81fd17030900 0f8584020000 837c244c01 }
		$sequence_6 = { 83c001 25fe010000 f20f593c8508708f00 660f122c8508708f00 03c0 660f28348520748f00 baef7f0000 }
		$sequence_7 = { 85c0 0f8486c10000 b801000000 e9???????? 8b44240c 25ffff0f00 0b442408 }
		$sequence_8 = { 83c40c ffb534faffff ffb524faffff 6aff 57 6a01 6a00 }
		$sequence_9 = { 83e2fe ff750c 50 8d45e8 50 8b4204 ffd0 }

	condition:
		7 of them and filesize <1785856
}