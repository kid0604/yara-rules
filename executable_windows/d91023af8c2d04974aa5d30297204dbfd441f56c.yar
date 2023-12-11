rule win_grabbot_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.grabbot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.grabbot"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83f85a 770d 83f841 7208 83c020 }
		$sequence_1 = { 0fb702 83f85a 770b 83f841 7206 83c020 }
		$sequence_2 = { 7206 83c020 0fb7c0 83c202 }
		$sequence_3 = { c745fc0f72a7dc 8145fc11111111 56 53 51 }
		$sequence_4 = { ad 3b450c 7406 e2f8 }
		$sequence_5 = { 53 8bd8 035b3c 66813b5045 5b 7407 2d00100000 }
		$sequence_6 = { c745c475726541 c745c864647265 66c745cc7373 c645ce00 }
		$sequence_7 = { 68391ef172 e8???????? 50 e8???????? ffe0 }
		$sequence_8 = { 56 ffd0 33c9 66894c37fe }
		$sequence_9 = { 89480c e9???????? 33c0 e9???????? }
		$sequence_10 = { 894804 8b0d???????? 894808 8b0d???????? 89480c e9???????? }
		$sequence_11 = { 7428 8b0d???????? 8908 8b0d???????? 894804 8b0d???????? }
		$sequence_12 = { 6a00 6840420f00 6a00 ff15???????? a3???????? 85c0 }
		$sequence_13 = { 85f6 741e 57 56 6aff }
		$sequence_14 = { 85c0 56 0f9fc3 e8???????? 83c414 }
		$sequence_15 = { 8bf0 85f6 741d 8d4601 50 e8???????? 8bf8 }

	condition:
		7 of them and filesize <1335296
}
