rule win_nokki_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.nokki."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nokki"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 33d2 68ce070000 52 }
		$sequence_1 = { e8???????? 33c9 68ce070000 51 }
		$sequence_2 = { c1f905 8bf0 83e61f 8d3c8d80054100 8b0f }
		$sequence_3 = { 4b 0fb60b 40 80b918e4400000 74e8 }
		$sequence_4 = { 837d0c00 0f840a010000 8b4508 85c0 0f84ff000000 }
		$sequence_5 = { e8???????? 50 e8???????? 8b8df0fdffff }
		$sequence_6 = { 6a00 ff15???????? 8bf8 85ff 0f8485000000 6a00 }
		$sequence_7 = { 50 c745cce0c74000 e8???????? 8b7508 bf63736de0 393e 0f85a5010000 }
		$sequence_8 = { 83e61f c1e606 03348580054100 c745e401000000 33db 395e08 }
		$sequence_9 = { 03ff 89bd3cd4ffff 81ff00000080 0f85f8fdffff 6a06 68???????? 8bce }

	condition:
		7 of them and filesize <454656
}
