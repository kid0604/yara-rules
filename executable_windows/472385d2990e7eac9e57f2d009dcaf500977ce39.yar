rule win_rustock_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.rustock."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rustock"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 21d0 83e100 85c9 7506 68db030100 c3 }
		$sequence_1 = { 85f6 7467 c745dc01000000 53 56 ff7510 ff750c }
		$sequence_2 = { e8???????? 85c0 7420 8d85fcfeffff 50 56 }
		$sequence_3 = { ff15???????? cc a1???????? 85c0 7402 ffd0 56 }
		$sequence_4 = { 7404 802700 47 ff06 8b5d0c }
		$sequence_5 = { 8d85fcfeffff 50 ff7508 ff15???????? 85c0 6a04 6a00 }
		$sequence_6 = { 895dbc 8bcf 33c0 8bfb 8bd1 c1e902 }
		$sequence_7 = { 8bf8 ff550c 68c5030000 8bd8 ff550c }
		$sequence_8 = { 53 ff15???????? 8d65ac 5f 5e 5b }
		$sequence_9 = { 8975c0 85f6 0f848b000000 8365fc00 83c003 83e0fc e8???????? }

	condition:
		7 of them and filesize <565248
}
