rule win_simda_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.simda."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.simda"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0faf5dfc 8bfa c1e710 0b7df4 3bdf }
		$sequence_1 = { 8b5508 83c40c 803a00 0f8491000000 53 8bda }
		$sequence_2 = { 33d2 3b7dec 7519 8b5dfc }
		$sequence_3 = { 0fb7c8 0fafd1 8bf9 c1e810 0faffb }
		$sequence_4 = { 8d95f5fdffff 33c9 53 52 }
		$sequence_5 = { 6803010000 33c9 8d95edfdffff 56 52 }
		$sequence_6 = { 03c7 3bc7 7301 42 }
		$sequence_7 = { 7c02 33c0 41 81f900010000 7ce4 }
		$sequence_8 = { ffd7 8b1d???????? 6a00 6a01 8d8df8feffff }
		$sequence_9 = { a1???????? 8dbc35c8fcffff 03d7 81e201000080 7905 }

	condition:
		7 of them and filesize <1581056
}
