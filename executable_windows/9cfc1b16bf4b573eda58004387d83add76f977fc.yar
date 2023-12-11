rule win_glasses_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.glasses."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.glasses"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e9???????? 8d8d60f7ffff e9???????? 8d8df8faffff e9???????? 8d8d30fbffff e9???????? }
		$sequence_1 = { e8???????? 8b35???????? 83c40c 6880000000 8d8df8feffff 51 ffd6 }
		$sequence_2 = { eb05 1bc9 83d9ff 85c9 0f844c130000 ba???????? 8bc8 }
		$sequence_3 = { e8???????? 8bce c745fc00000000 e8???????? 8d8d7cffffff e8???????? 8d857cffffff }
		$sequence_4 = { eb09 8b4508 50 e8???????? 83c40c 85c0 0f94c0 }
		$sequence_5 = { e8???????? 57 50 8bcb e8???????? 53 8bce }
		$sequence_6 = { e9???????? 8d8df0feffff e9???????? 8d8d44ffffff e9???????? 8d8d7cffffff e9???????? }
		$sequence_7 = { e9???????? e8???????? 8d4e10 e8???????? 85c0 7505 a1???????? }
		$sequence_8 = { f7e1 c1ea06 8955f0 69d2e8030000 2bca 69c9e8030000 6800100000 }
		$sequence_9 = { e8???????? 8d8d40f8ffff c645fc03 e8???????? 8d8da0f8ffff c645fc02 e8???????? }

	condition:
		7 of them and filesize <4177920
}
