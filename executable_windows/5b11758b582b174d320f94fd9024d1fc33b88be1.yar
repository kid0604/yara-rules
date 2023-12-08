rule win_onliner_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.onliner."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.onliner"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8bc8 8b55f8 8bc3 8b18 ff5324 33c0 5a }
		$sequence_1 = { 8b45fc e8???????? 8bc8 8b55f8 8bc3 8b18 ff5324 }
		$sequence_2 = { ba???????? e8???????? 8b45e8 33d2 e8???????? 8bf0 }
		$sequence_3 = { 8bc5 e8???????? 837c240400 7592 8d4c2404 8b5304 8b03 }
		$sequence_4 = { 8d1430 8b45f4 8b4dec e8???????? 8bcf 49 034df0 }
		$sequence_5 = { 56 ff15???????? 5a 5e }
		$sequence_6 = { 2bd0 8955f0 8b55f0 3b4208 740f c705????????0a000000 e9???????? }
		$sequence_7 = { 56 57 33c9 894d8c 8bfa 8945a0 8b45a0 }
		$sequence_8 = { 56 57 8bfa 8bf0 837e6c00 7405 b001 }
		$sequence_9 = { 2bd0 3bf2 76a7 33c0 890424 8b0424 59 }

	condition:
		7 of them and filesize <1736704
}
