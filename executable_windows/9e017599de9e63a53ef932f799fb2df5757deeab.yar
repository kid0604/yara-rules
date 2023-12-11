rule win_unidentified_042_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.unidentified_042."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_042"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { d1c6 8975a8 8b75fc 33f3 3375f0 8b5df0 0375a8 }
		$sequence_1 = { 0f8d85000000 8d55c4 52 8bc2 50 e8???????? }
		$sequence_2 = { 6a02 8d5e1c 50 8b8774020000 8bf3 e8???????? }
		$sequence_3 = { 8bc1 52 0fb655ff c1e80a 83e001 50 0fb7837e010000 }
		$sequence_4 = { c78524ffffff3fd27290 c78528ffffffae4e840c c7852cffffff79ca6988 c78530ffffff90060984 c78534fffffffa024380 c78538ffffff893ec3fc c7853cffffff05ba3078 }
		$sequence_5 = { 03f7 898d7cefffff ff15???????? 8bbd64efffff 33c0 83c40c 898568efffff }
		$sequence_6 = { 8bce e8???????? 8b45f8 83c410 85c0 0f8506010000 }
		$sequence_7 = { eb0f 8b8e38020000 8d7901 89be38020000 8bd9 c1eb18 885804 }
		$sequence_8 = { 5d c3 8bb59cfeffff 8d95a0feffff 52 56 e8???????? }
		$sequence_9 = { 8bd6 e8???????? 83c40c 8945fc 5f 8be5 5d }

	condition:
		7 of them and filesize <516096
}
