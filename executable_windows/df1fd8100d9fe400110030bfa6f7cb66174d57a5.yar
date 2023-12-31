rule win_ransoc_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.ransoc."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ransoc"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 56 8bf8 e8???????? 83c410 83ffff }
		$sequence_1 = { 6a00 6817c00000 6a00 6a00 }
		$sequence_2 = { 838eb400000002 85c0 740c 8d9688000000 52 ffd0 }
		$sequence_3 = { 7403 897a44 8b513c 897144 8b7238 89713c 3bf7 }
		$sequence_4 = { 8bc7 e8???????? 8bc7 6a10 }
		$sequence_5 = { c7402c20000000 c7400801000000 56 8d5010 8d7108 8932 }
		$sequence_6 = { 25fffeffff 014e40 89462c 7518 }
		$sequence_7 = { 8b442438 8b4c2420 8b542424 8908 8b4c2428 5e }
		$sequence_8 = { 895140 8b4830 85c9 7406 8b5034 895134 }
		$sequence_9 = { 83c618 56 e8???????? 83c40c 5e c3 }

	condition:
		7 of them and filesize <958464
}
