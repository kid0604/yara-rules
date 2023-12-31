rule win_asprox_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.asprox."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.asprox"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 85c0 752c 8b4d10 8b11 52 8b45f8 50 }
		$sequence_1 = { 837b2001 7cc3 8b5320 8b431c 8d4aff d3e8 8b4dfc }
		$sequence_2 = { 50 ff15???????? 83c404 8b8dacfbffff 51 ff15???????? 83c404 }
		$sequence_3 = { 7cde 8b4dfc 89848de0fbffff 83fa01 0f8f37feffff 8b7d10 33d2 }
		$sequence_4 = { 8b4210 8a5108 8810 8b91600c0000 0fb65908 }
		$sequence_5 = { 8b15???????? 52 ff15???????? 898548feffff 6800100000 6a00 a1???????? }
		$sequence_6 = { 6a01 68???????? 6a00 8d85fcfdffff 50 ff15???????? 6800100000 }
		$sequence_7 = { 57 395d08 0f8498000000 8b750c 3bf3 0f848d000000 8b7d10 }
		$sequence_8 = { 50 ff15???????? c745e800000000 c7856cffffff00000000 8d4df4 51 8d956cffffff }
		$sequence_9 = { 8b450c 8b4d10 c6044100 8be5 }

	condition:
		7 of them and filesize <155648
}
