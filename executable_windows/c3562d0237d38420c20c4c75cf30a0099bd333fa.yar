rule win_bluehaze_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.bluehaze."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bluehaze"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8d8d18fdffff 897d94 897590 c6458000 c745fcffffffff e8???????? 8b4df4 }
		$sequence_1 = { 8b4d0c b8d34d6210 f76978 56 c1fa06 8bf2 c1ee1f }
		$sequence_2 = { 89b570fbffff 899d6cfbffff 889d5cfbffff e9???????? 8bcf 83ff07 7205 }
		$sequence_3 = { ff15???????? 3b45e8 7508 3bd7 0f8489000000 c745ec04000000 8b16 }
		$sequence_4 = { 51 e8???????? 83c404 8bce c7462c00000000 e8???????? f6c301 }
		$sequence_5 = { b001 884110 8b5604 884211 897dfc 8845fc 8b4508 }
		$sequence_6 = { 8b450c 83c01c 50 8bce e8???????? 8bc6 5e }
		$sequence_7 = { 894de4 85f6 7462 8b4dc0 8d0431 8945bc 6a10 }
		$sequence_8 = { c745e80f000000 897de4 c645d400 8b4654 8b1d???????? 50 897dfc }
		$sequence_9 = { ff15???????? 3d6d270000 7573 8d856cfeffff 50 6801010000 ff15???????? }

	condition:
		7 of them and filesize <424960
}
