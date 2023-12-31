rule win_tiger_rat_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.tiger_rat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tiger_rat"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 41b801000000 488bd7 ff5028 85c0 754e 488b5d90 488bcb }
		$sequence_1 = { 03c2 448bd0 83e007 41c1fa03 }
		$sequence_2 = { 017720 488b4b20 e8???????? 84c0 }
		$sequence_3 = { 03c1 4103c2 25ff000080 7d09 }
		$sequence_4 = { 03e8 33ff ffc6 83fe1a }
		$sequence_5 = { 03d8 3bdf 7cdd 488b5c2430 }
		$sequence_6 = { 03c2 448bc0 83e007 41c1f803 2bc2 4963d0 }
		$sequence_7 = { 03c2 448bc0 83e007 2bc2 41c1f803 85c0 }
		$sequence_8 = { e8???????? 8bd8 e8???????? 2bc3 3d70170000 }
		$sequence_9 = { e8???????? 85c0 0f85d9000000 488d15d0c90000 41b810200100 488bcd }
		$sequence_10 = { e8???????? 8b05???????? 488d4c2440 0b05???????? }
		$sequence_11 = { 8b05???????? 488d3562000200 660f6f05???????? f30f7f4507 }
		$sequence_12 = { e8???????? 488d5b28 48ffcd 75dc 4c8bb42490000000 8b8e90000000 }
		$sequence_13 = { 4533c0 4c894310 448803 443802 7414 }
		$sequence_14 = { 4053 4883ec20 488d0513880100 488bd9 c605????????00 488901 }
		$sequence_15 = { c74424201e000000 488bd8 ff15???????? 488d542430 }

	condition:
		7 of them and filesize <557056
}
