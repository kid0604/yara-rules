rule win_buer_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.buer."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.buer"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b4014 8b00 8b4010 8945fc 61 8b45fc }
		$sequence_1 = { 7507 e8???????? eb05 e8???????? 46 83fe20 7cd1 }
		$sequence_2 = { 60 64a130000000 8b400c 8b4014 8b00 8b4010 }
		$sequence_3 = { 8bc2 eb19 33c0 85d2 7e13 3bc7 }
		$sequence_4 = { 8b55e8 015158 8b55d8 894148 8b45dc 03c6 89414c }
		$sequence_5 = { c1e104 0bc8 6a02 5b }
		$sequence_6 = { 8945f8 ff15???????? 59 59 85c0 }
		$sequence_7 = { 8365fc00 53 56 57 60 64a130000000 8b400c }
		$sequence_8 = { c744240402000000 8d442428 c7442408???????? c744240c01000000 }
		$sequence_9 = { e8???????? 80fb03 7705 80fb02 }
		$sequence_10 = { e8???????? 0f0b b92c000000 ba01000000 e8???????? 0f0b 89f9 }
		$sequence_11 = { c744240401000000 c7442408???????? c744240c01000000 89442410 }
		$sequence_12 = { e8???????? 56 6a00 50 e8???????? c7471c01000000 }
		$sequence_13 = { c744240800000000 57 e8???????? 85c0 }
		$sequence_14 = { cd29 0f0b cc 8b442404 833800 7406 ba???????? }
		$sequence_15 = { e8???????? 80fb05 ba01000000 0fb6c3 }

	condition:
		7 of them and filesize <3031040
}
