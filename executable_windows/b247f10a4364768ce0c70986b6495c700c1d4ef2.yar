rule win_quantloader_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.quantloader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.quantloader"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c744240801000000 c7442404???????? 8b4508 890424 e8???????? 48 }
		$sequence_1 = { c744240400000000 8d45a8 890424 e8???????? c745a844000000 }
		$sequence_2 = { 89442404 8b45f0 890424 e8???????? 83ec10 }
		$sequence_3 = { 890424 e8???????? 83ec04 ebe2 55 }
		$sequence_4 = { 83ec28 c745fc01000000 8d45f8 89442408 8b450c 89442404 }
		$sequence_5 = { e8???????? 3945f8 0f8349020000 c744240801000000 8b45f8 89442404 }
		$sequence_6 = { c745d401000000 8d4598 89442424 8d45a8 }
		$sequence_7 = { 55 89e5 83ec18 c745fc0a000000 c605????????00 8b45fc }
		$sequence_8 = { c3 60 8bd3 8bf2 }
		$sequence_9 = { 7409 81ee01100000 4e ebec 8d5efe 84ff }
		$sequence_10 = { 85f6 0f8481000000 03f3 ad }
		$sequence_11 = { 58 ffd0 837c240802 7414 64a118000000 }
		$sequence_12 = { 52 50 6a04 6800100000 57 }
		$sequence_13 = { 83e804 50 ff30 6800100000 }
		$sequence_14 = { 54 50 51 57 ff550c 58 83c614 }
		$sequence_15 = { 33c0 ab 61 c3 60 ff553c }

	condition:
		7 of them and filesize <155648
}
