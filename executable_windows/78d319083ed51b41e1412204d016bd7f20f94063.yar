rule win_salgorea_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.salgorea."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.salgorea"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 66c1e303 f6d1 f8 6633d2 66b8b96a 66b9ada1 66f7f1 }
		$sequence_1 = { 8b5c240c 53 9d 8b5c2404 }
		$sequence_2 = { 51 6698 f7db 33d2 b889510000 b98c0b0000 }
		$sequence_3 = { 66c1e804 8b44240c 0fbafa00 0fbcd2 }
		$sequence_4 = { 8b5c240c 53 d50a 48 d40a 22c9 }
		$sequence_5 = { 66c1e306 80eb38 80e6ee f8 f6d1 52 40 }
		$sequence_6 = { 8b5c2404 f8 99 8b1424 f5 66f7d8 8b442410 }
		$sequence_7 = { 51 66b9b469 66f7f1 f7da }
		$sequence_8 = { a1???????? 8945cc 8d45cc 3930 }
		$sequence_9 = { 8d85fcfeffff 33f6 8d4801 8a10 }
		$sequence_10 = { 8d85fcfeffff 50 6812270000 ffb5f8feffff }
		$sequence_11 = { 8d85fcfeffff 50 6820270000 ffb5f8feffff }
		$sequence_12 = { 8d85fcfeffff 50 e8???????? 83c40c 8d85fcfeffff 33f6 }
		$sequence_13 = { 8d8610030000 50 e8???????? 81c628030000 }
		$sequence_14 = { 8d85fcfeffff 53 50 e8???????? 83c40c 8d5dc4 }
		$sequence_15 = { 8d85fcfeffff 50 ff750c be80000000 }

	condition:
		7 of them and filesize <2007040
}
