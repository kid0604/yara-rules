rule win_mrdec_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.mrdec."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mrdec"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 68???????? 57 e8???????? 8d45e0 50 57 6800000080 }
		$sequence_1 = { e8???????? ff75f8 e8???????? 83f8ff 7402 eb45 }
		$sequence_2 = { 8bec 83c4c8 c745c800000000 6a00 6a00 6a00 68???????? }
		$sequence_3 = { 50 e8???????? 68???????? 6a00 6a00 6814010000 68???????? }
		$sequence_4 = { 55 8bec 81c488fdffff 8d85a8fdffff 50 }
		$sequence_5 = { ff35???????? e8???????? 83c70c ff4dcc }
		$sequence_6 = { 6a00 ff35???????? e8???????? 83f801 7405 e9???????? ff75e4 }
		$sequence_7 = { 50 ff75e0 e8???????? 3dea000000 }
		$sequence_8 = { e8???????? 8945d8 6a00 8d45cc }
		$sequence_9 = { ff75fc e8???????? 8b4508 0520800000 6a01 }

	condition:
		7 of them and filesize <44864
}
