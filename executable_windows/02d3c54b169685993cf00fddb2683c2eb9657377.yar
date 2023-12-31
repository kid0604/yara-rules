rule win_mount_locker_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.mount_locker."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mount_locker"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { f30f5905???????? 0f5ad0 66490f7ed0 e8???????? }
		$sequence_1 = { 4c8b05???????? 488bcb 488b15???????? e8???????? 85c0 }
		$sequence_2 = { 488b0b 41b902000000 4533c0 33d2 }
		$sequence_3 = { 488d4df0 4889442428 4533c9 4533c0 }
		$sequence_4 = { 4533c9 488b4c2458 33d2 c744243001000000 }
		$sequence_5 = { 4d8bc8 4c8bc2 4c8bf2 8bf1 33d2 33c9 }
		$sequence_6 = { 81f900000780 7503 0fb7c0 3d2e050000 }
		$sequence_7 = { 8bc8 81e10000ffff 81f900000780 7503 }
		$sequence_8 = { ff15???????? 85c0 7509 f0ff05???????? }
		$sequence_9 = { 33c9 4c89742438 4c89742430 41d1e9 c744242804010000 }
		$sequence_10 = { 7505 e8???????? 833d????????00 7409 833d????????00 }
		$sequence_11 = { 4803c8 4c2bc0 e8???????? 32c0 }
		$sequence_12 = { 6a03 e8???????? 833d????????00 59 }
		$sequence_13 = { 5e 59 c3 81ec08020000 56 }
		$sequence_14 = { ff15???????? eb03 6a08 5b ff74241c e8???????? }
		$sequence_15 = { 8d4db8 51 e8???????? 33c0 83c40c }

	condition:
		7 of them and filesize <368640
}
