rule win_hui_loader_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.hui_loader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hui_loader"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { a3???????? e8???????? 8db6dcb90010 bf???????? }
		$sequence_1 = { 50 53 c7442420c8910010 ff15???????? }
		$sequence_2 = { c1f905 8bc6 8b0c8d60e20010 8d04c0 80648104fd }
		$sequence_3 = { ff15???????? 8b742410 bf2c010000 8b16 52 e8???????? 83c404 }
		$sequence_4 = { a1???????? ffd0 68e8030000 ffd6 8b0d???????? }
		$sequence_5 = { ff15???????? a1???????? 8b3d???????? 8bf3 53 8d4801 8bd1 }
		$sequence_6 = { ff15???????? c20400 8b0d???????? 68???????? 51 }
		$sequence_7 = { e8???????? ffb604b40010 8d8560ffffff 50 e8???????? }
		$sequence_8 = { 7423 8bce 8bc6 c1f905 83e01f 8b0c8d60e20010 8d04c0 }
		$sequence_9 = { 83e203 83f908 7229 f3a5 ff2495c8540010 8bc7 }

	condition:
		7 of them and filesize <131072
}
