rule win_darkmoon_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.darkmoon."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkmoon"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c9 c20400 837dd84b 74ab ebbc }
		$sequence_1 = { 64657273 006801 0000 80ff56 35c745fc04 }
		$sequence_2 = { c1ef02 eb0b 8b55e4 c1ef02 83e203 03fa }
		$sequence_3 = { 51 50 50 8d860f040000 }
		$sequence_4 = { 8dbd8cf0ffff 57 ff96a9000000 c7857cf0ffff00000000 83857cf0ffff01 ffb57cf0ffff }
		$sequence_5 = { 8b742414 83fe3c 7c29 b889888888 b93c000000 f7ee }
		$sequence_6 = { 57 ff7510 ff7514 50 ff750c ff96b5000000 58 }
		$sequence_7 = { 6802000080 ff5735 c7852cefffff04010000 8d852cefffff 50 }
		$sequence_8 = { 8d55ec 6a00 52 8d85c0fdffff }
		$sequence_9 = { 7c27 b889888888 8b742414 f7ef 03d7 b93c000000 }

	condition:
		7 of them and filesize <98304
}
