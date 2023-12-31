rule win_mmon_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.mmon."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mmon"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83feff 7e5b eb03 8b5508 0fbe1416 52 e8???????? }
		$sequence_1 = { 3975e4 7303 8d45d0 8b8d54ffffff 8b11 8910 }
		$sequence_2 = { 40 cd40 0064cd40 008ccd40008a46 0323 d188470383ee }
		$sequence_3 = { 899554ffffff 898548ffffff 8d642400 8a07 3c30 }
		$sequence_4 = { 50 ff15???????? ffd6 50 e8???????? 8b44241c }
		$sequence_5 = { 8b17 68???????? 51 52 }
		$sequence_6 = { ebd2 8bc3 c1f805 8d3c85606a4200 8bf3 83e61f c1e606 }
		$sequence_7 = { c7854cffffff00000000 b801000000 018554ffffff 018548ffffff 03f8 3bbd50ffffff }
		$sequence_8 = { 8b0d???????? 85c9 7406 8b55ec }
		$sequence_9 = { 6a00 8bf1 c745d000000000 ff15???????? 8bf8 33c0 4f }

	condition:
		7 of them and filesize <356352
}
