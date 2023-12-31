rule win_bagle_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.bagle."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bagle"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { b03d f3aa 5b 5f 5e c9 }
		$sequence_1 = { c745f400000000 6a06 6a01 6a02 e8???????? 8bd8 ff7508 }
		$sequence_2 = { e340 ac c1e010 83f901 740b }
		$sequence_3 = { c9 c20c00 c1c206 8bc2 }
		$sequence_4 = { f7d9 2bf9 b03d f3aa 5b 5f 5e }
		$sequence_5 = { 68???????? e8???????? 0bc0 7426 6880000000 68???????? e8???????? }
		$sequence_6 = { c20c00 c1c206 8bc2 243f 3c3e }
		$sequence_7 = { 53 8b7508 8b7d0c 8b4d10 }
		$sequence_8 = { 59 43 83fb12 7508 33db }
		$sequence_9 = { e8???????? 58 c9 c20400 55 8bec 83c4f8 }

	condition:
		7 of them and filesize <245760
}
