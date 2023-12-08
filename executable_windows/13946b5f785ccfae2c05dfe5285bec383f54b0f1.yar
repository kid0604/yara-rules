rule win_mydoom_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.mydoom."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mydoom"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 89442404 891c24 e8???????? 85c0 0f849f000000 }
		$sequence_1 = { 0fb65301 8b4510 8810 0fbe4303 83f803 7459 83f803 }
		$sequence_2 = { 83f8ff 7430 895c2408 8d85f8feffff 89442404 }
		$sequence_3 = { 0fb65e01 803e01 0f95c0 84db 0f94c2 09d0 }
		$sequence_4 = { c744240810000000 8d45c8 89442404 891c24 e8???????? 83ec0c 83f8ff }
		$sequence_5 = { 890424 e8???????? c9 83f801 }
		$sequence_6 = { 81ec38010000 895df4 8975f8 897dfc 8b7d08 }
		$sequence_7 = { c744240402000000 8d8548ffffff 890424 e8???????? 83ec08 }
		$sequence_8 = { 890424 e8???????? e8???????? 8db406fc2f0000 0fb745e6 }
		$sequence_9 = { 0fbe45b7 89442404 8d5db8 891c24 e8???????? }

	condition:
		7 of them and filesize <114688
}
