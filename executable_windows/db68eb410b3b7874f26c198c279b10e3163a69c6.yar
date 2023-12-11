rule win_hacksfase_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.hacksfase."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hacksfase"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7435 50 ffd6 5f 5e }
		$sequence_1 = { 895e24 895e28 740d 50 ff15???????? 895e30 895e2c }
		$sequence_2 = { 53 51 ff7628 895dbc 895dc4 895dc0 895dc8 }
		$sequence_3 = { 832600 83c60c 4b 75ef 5e }
		$sequence_4 = { 51 8b0d???????? 89842418040000 e8???????? b9???????? e8???????? }
		$sequence_5 = { a806 746c b9???????? c78424bc02000003000000 c78424c002000002000000 c78424c4020000ffffffff c78424b802000010000000 }
		$sequence_6 = { 8b35???????? 85f6 7412 6a00 8bce e8???????? }
		$sequence_7 = { a1???????? 85c0 7428 50 ff15???????? 83c404 85c0 }
		$sequence_8 = { 0f8400030000 ebbb c744241400000000 8b442414 83c9ff }
		$sequence_9 = { 5f c3 55 8bec 51 8a4108 8365fc00 }

	condition:
		7 of them and filesize <106496
}
