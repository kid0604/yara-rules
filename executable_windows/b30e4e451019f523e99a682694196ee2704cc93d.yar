rule win_bughatch_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.bughatch."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bughatch"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 817de4c8000000 7566 837d1000 7460 b901000000 85c9 7457 }
		$sequence_1 = { 52 e8???????? 83c408 8945dc c745f800000000 }
		$sequence_2 = { 55 8bec 83ec1c c745f400000000 c745fcffffffff c745f8ffffffff c745e800000000 }
		$sequence_3 = { 83c404 8945f8 837df800 7427 8b4df8 51 8b55e8 }
		$sequence_4 = { 6a00 6a01 8b5514 52 8d85c4feffff 50 }
		$sequence_5 = { c6840d94f7ffff00 68???????? 8d9594f7ffff 52 ff15???????? 8b4508 50 }
		$sequence_6 = { 8d441202 8b4dec 89410c 8b55ec 8b420c 8b4d0c }
		$sequence_7 = { 8b5514 52 6a00 8b45fc 50 }
		$sequence_8 = { e8???????? 83c404 8945fc 68???????? ff15???????? 833d????????00 }
		$sequence_9 = { 50 8d4dec 51 8d95e4fdffff 52 8d45e8 50 }

	condition:
		7 of them and filesize <75776
}
