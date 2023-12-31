rule win_prilex_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.prilex."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prilex"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 2b4814 898de8feffff 8b55ac 8b85e8feffff }
		$sequence_1 = { c7850cffffff08000000 8b45c4 50 8d4dac 51 }
		$sequence_2 = { 8b85f0feffff 50 ff5220 dbe2 8985ecfeffff 83bdecfeffff00 }
		$sequence_3 = { 8b17 6a00 6aff 6a01 68???????? 8d8dacfdffff }
		$sequence_4 = { 8b55c8 52 e8???????? ff15???????? c745fc24000000 }
		$sequence_5 = { 8bf0 ff15???????? 8d45c8 8d4dcc 50 51 }
		$sequence_6 = { ff15???????? 8d85f8feffff 50 8d4da8 51 8d55c8 }
		$sequence_7 = { c745fc0d000000 8d45c8 50 68ff000000 }
		$sequence_8 = { 83c420 6685f6 7431 8b17 }
		$sequence_9 = { 52 ff15???????? 50 8b4508 8b08 51 57 }

	condition:
		7 of them and filesize <450560
}
