rule win_albaniiutas_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.albaniiutas."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.albaniiutas"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83ec0c 53 56 57 68000000f0 6a18 }
		$sequence_1 = { 23c1 eb55 8b1c9dd83e0110 56 6800080000 6a00 }
		$sequence_2 = { 8b7e04 897df8 83bb8400000000 0f86d0000000 8b9b80000000 6a14 03df }
		$sequence_3 = { c745e840df1700 c745e400000000 c745e000000000 c745dc00000000 c745fc00000000 }
		$sequence_4 = { e9???????? 8b4508 c74018d81a0110 c74104513f0000 e9???????? 83fe10 732d }
		$sequence_5 = { 0fb6c3 331485c0280110 335604 8bca }
		$sequence_6 = { c74018c41b0110 c74104513f0000 e9???????? 8d8134050000 }
		$sequence_7 = { 6bc830 894de0 8b049d90df0210 0fb6440828 83e001 7469 }
		$sequence_8 = { 7429 8b4dfc 83c704 83c604 833f00 }
		$sequence_9 = { e9???????? 8b4508 8b4df8 c74018c41b0110 c74104513f0000 e9???????? }

	condition:
		7 of them and filesize <566272
}
