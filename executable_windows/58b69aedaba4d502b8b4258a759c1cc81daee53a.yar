rule win_maggie_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.maggie."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.maggie"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83f8ff 750f ff15???????? 2d33270000 f7d8 }
		$sequence_1 = { 83f8ff 750f ff15???????? 2d33270000 }
		$sequence_2 = { 750a b857000000 e9???????? ff15???????? 3905???????? 740a b8dd100000 }
		$sequence_3 = { ff15???????? 83f8ff 750f ff15???????? 2d33270000 f7d8 }
		$sequence_4 = { 750a b857000000 e9???????? ff15???????? 3905???????? 740a }
		$sequence_5 = { 750a b857000000 e9???????? ff15???????? 3905???????? }
		$sequence_6 = { b8ff000000 663b05???????? 7505 e8???????? }
		$sequence_7 = { 663b05???????? 7505 e8???????? e8???????? 84c0 }
		$sequence_8 = { 750f ff15???????? 2d33270000 f7d8 1bc0 }
		$sequence_9 = { 750a b857000000 e9???????? ff15???????? }

	condition:
		7 of them and filesize <611328
}