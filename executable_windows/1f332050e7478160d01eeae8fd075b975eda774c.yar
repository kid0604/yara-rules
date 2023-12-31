rule win_zedhou_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.zedhou."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zedhou"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8d4d8c 51 8d559c 52 ff15???????? 8d459c 50 }
		$sequence_1 = { e8???????? 85c0 751f e8???????? 3d33270000 7507 c7460c06000000 }
		$sequence_2 = { ff15???????? 8d4dc0 ff15???????? c745fc0a000000 8b4dd8 51 }
		$sequence_3 = { 8b4d08 8b514c 8b420c 8b8d88feffff 8a9534ffffff 881408 8d8d6cffffff }
		$sequence_4 = { e8???????? 8bf8 8d8603010000 6800040000 50 ff742414 8bcf }
		$sequence_5 = { 0f8588020000 85d2 0f847b020000 8b4a40 8d4240 50 894500 }
		$sequence_6 = { ff5074 8b8e24070000 8d55f0 6a10 52 8b01 }
		$sequence_7 = { 85c0 0f95c1 03d7 03ca 894df8 7511 b880010480 }
		$sequence_8 = { 52 ff15???????? 89858cfdffff eb0a c7858cfdffff00000000 833d????????00 751c }
		$sequence_9 = { 50 8bf8 8b08 ff517c 85c0 dbe2 7d0b }

	condition:
		7 of them and filesize <499712
}
