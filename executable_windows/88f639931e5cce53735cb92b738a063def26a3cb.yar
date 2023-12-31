rule win_alma_communicator_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.alma_communicator."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.alma_communicator"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83f802 7509 80bdfdfdffff3a 7429 }
		$sequence_1 = { 50 6a00 ffd3 ba???????? 8d8dfcfdffff e8???????? }
		$sequence_2 = { 8bf0 ff15???????? 889dd4ebffff 83fe01 }
		$sequence_3 = { 75f4 8bca 33c0 c1e902 f3a5 }
		$sequence_4 = { 8945fc 85ff 7416 8b45f4 }
		$sequence_5 = { e8???????? 8bcb 898554f7ffff e8???????? 8bcb 898550f7ffff 6a02 }
		$sequence_6 = { f20f5905???????? e8???????? 05e8030000 50 e8???????? }
		$sequence_7 = { 8b1485f08f4100 8a4c1a2d f6c104 7419 8a441a2e 80e1fb 8845f4 }
		$sequence_8 = { 8d55e8 8bf2 33c9 6a02 5f }
		$sequence_9 = { e8???????? 8b4dfc 83c40c 33cd 33c0 5b e8???????? }

	condition:
		7 of them and filesize <245760
}
