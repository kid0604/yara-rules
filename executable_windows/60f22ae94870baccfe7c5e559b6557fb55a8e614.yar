rule win_unidentified_092_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.unidentified_092."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_092"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8bf1 66833c465c 7405 40 3bc7 72d7 5e }
		$sequence_1 = { 8bcb c1c902 33d1 8bcb 0b4dfc 03d6 234df4 }
		$sequence_2 = { e8???????? c745fc08000000 83cb08 68???????? 8bc8 899d64feffff }
		$sequence_3 = { e8???????? 8bf8 c745fc00000000 8b4de8 0fb75112 8d8d70ffffff }
		$sequence_4 = { 897dec 8bcb c1c902 33d1 8b4df8 0bcb 03d6 }
		$sequence_5 = { ff750c 6a12 50 e8???????? 83c414 }
		$sequence_6 = { 830640 c7460800000000 83560400 85db 7443 83fb40 7224 }
		$sequence_7 = { 81e3fffdffff e8???????? f7c300010000 7411 8d8dd0fdffff 81e3fffeffff e8???????? }
		$sequence_8 = { 57 c645ea21 c645e95e c645e840 ffd6 6a00 6a01 }
		$sequence_9 = { 8d55c8 52 c745c800000000 6a07 8b08 50 ff5128 }

	condition:
		7 of them and filesize <10202112
}