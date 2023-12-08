rule win_torisma_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.torisma."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.torisma"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c1e90e 83e101 33c1 488b4c2450 8b4974 c1e90a }
		$sequence_1 = { 488b39 33c0 488b4c2458 f3aa c744244400000000 c744243000000000 488b842480000000 }
		$sequence_2 = { 668944242e b85c000000 6689442430 b866000000 6689442432 b862000000 }
		$sequence_3 = { ff15???????? 4889442428 48837c242800 741b 488d1570610100 }
		$sequence_4 = { 8b4954 c1e90a 83e101 33c1 488b4c2450 8b4960 c1e916 }
		$sequence_5 = { 33d2 488b442450 488b4810 ff15???????? 85c0 740a 8b442470 }
		$sequence_6 = { 48837c244800 741d 488b442448 4889442470 488b4c2470 e8???????? 48c744244800000000 }
		$sequence_7 = { 4889442420 4c8d4c2440 41b83c040000 488b542460 488b4c2468 e8???????? e8???????? }
		$sequence_8 = { 8b4050 c1e818 83e001 488b4c2450 8b4964 c1e918 83e101 }
		$sequence_9 = { 48898424d0000000 488b8c24d0000000 e8???????? 48c744246000000000 }

	condition:
		7 of them and filesize <322560
}
