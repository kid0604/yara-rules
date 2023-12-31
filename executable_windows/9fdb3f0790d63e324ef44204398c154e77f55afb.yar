rule win_suppobox_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.suppobox."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.suppobox"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7d10 a1???????? 0b05???????? a3???????? }
		$sequence_1 = { 7f10 a1???????? 2305???????? a3???????? }
		$sequence_2 = { 8945f0 a1???????? 83e801 a3???????? }
		$sequence_3 = { 7e10 a1???????? 0305???????? a3???????? }
		$sequence_4 = { 890d???????? e8???????? 8bf0 e8???????? 03f0 }
		$sequence_5 = { 7d10 a1???????? 3305???????? a3???????? }
		$sequence_6 = { 3bc8 7d10 a1???????? 2b05???????? a3???????? }
		$sequence_7 = { 01bdacf7ffff 83c40c 83bdc8f7ffff00 8b95c8f7ffff }
		$sequence_8 = { 8d45f3 83ec04 890424 e8???????? }
		$sequence_9 = { 8d45f3 890424 e8???????? 52 ebc5 }
		$sequence_10 = { 8d45f4 89442408 e9???????? 8b4508 }
		$sequence_11 = { 01c6 39fe 0f8d7e010000 80bc2ef4f7ffff0a }
		$sequence_12 = { 8d45f2 89f1 89442404 c70424???????? }
		$sequence_13 = { 01d8 3b85b0f7ffff 7e2f 8b95c8f7ffff }
		$sequence_14 = { 8d45f2 89442404 8b4508 890424 e8???????? 83ec08 }
		$sequence_15 = { 8d45ef 89d9 890424 e8???????? 51 }
		$sequence_16 = { 01d7 68???????? 57 e8???????? }
		$sequence_17 = { 01c6 ebdb ff7510 57 }
		$sequence_18 = { 01c9 4a 79f2 833b54 }
		$sequence_19 = { 8d45f4 89442408 c744240401000000 893424 }
		$sequence_20 = { 01c6 39fe 0f8d2f020000 80bc2ef4f7ffff0a }
		$sequence_21 = { 019dacf7ffff 83c40c 299dc4f7ffff e9???????? }

	condition:
		7 of them and filesize <1875968
}
