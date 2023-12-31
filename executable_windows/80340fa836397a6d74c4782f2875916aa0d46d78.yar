rule win_playwork_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.playwork."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.playwork"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 57 6a7f 8dbdf2fdffff 59 }
		$sequence_1 = { 83c318 ff45f8 8b45f8 3b45f4 0f8246feffff 33db 395dfc }
		$sequence_2 = { 3314b5344b3f00 8b348d34573f00 8b4ddc c1eb10 0fb6fb c1e908 3334bd34533f00 }
		$sequence_3 = { 33db 683f000f00 53 53 ff15???????? 3bc3 }
		$sequence_4 = { 56 8d45f4 8b3d???????? 56 50 }
		$sequence_5 = { 8d85e4ecffff 56 53 50 e8???????? 56 8d85e4f4ffff }
		$sequence_6 = { 6a10 50 e8???????? 83c444 395d08 7504 }
		$sequence_7 = { 8b349534573f00 c1e910 0fb6c9 3358f8 33348d34533f00 8b4ddc c1e908 }
		$sequence_8 = { 56 66ab 56 8d45f4 }
		$sequence_9 = { e8???????? 8d858cfdffff 56 50 e8???????? 83c414 85c0 }

	condition:
		7 of them and filesize <360448
}
